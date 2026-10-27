//! «Остановить оригинал…»: [`ask_stop_original`] shows the original NCALayer found holding
//! the port and asks before it is ended. Stopping it (and starting wss on the freed port) is a
//! job ([`worker`]) while the window waits; then the window shows how it went. One window at a
//! time; its texts are composed here.

use std::cell::{Cell, RefCell};
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use oncl_basics::Locale;
use slint::{CloseRequestResponse, ComponentHandle, PlatformError, SharedString};

use crate::foreground;
use crate::prompter::select_desktop_language;
use crate::ui::StopOriginalWindow;
use crate::windows::{self, Desktop};
use crate::worker::{self, JobWindow, run, with};

/// How stopping the original came out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// It is stopped, and wss serves on the port now.
    Serving,
    /// It is stopped, but wss did not start: why, for the user.
    WssOff(String),
}

/// The original NCALayer found holding the port, and how to stop it.
pub struct StopOriginal {
    pub port: u16,
    /// Its program.
    pub exe: PathBuf,
    pub pid: u32,
    /// Stops it and starts wss on the port, telling the user why not in the language
    /// given. Runs on a worker thread, again if the user tries again after a failure.
    pub stop: Box<dyn Fn(Locale) -> io::Result<Stopped> + Send + Sync>,
}

/// The open window. Its callbacks find it by `id` in [`OPEN`], so that none holds it (a
/// reference cycle) and a late result never reaches a window opened since.
struct Open {
    id: u64,
    ui: StopOriginalWindow,
    desktop: Rc<Desktop>,
    request: Arc<StopOriginal>,
}

thread_local! {
    static OPEN: RefCell<Option<Rc<Open>>> = const { RefCell::new(None) };
    static NEXT_ID: Cell<u64> = const { Cell::new(0) };
}

fn current(id: u64) -> Option<Rc<Open>> {
    OPEN.with_borrow(|open| open.as_ref().filter(|o| o.id == id).cloned())
}

/// Whether the window is open.
pub(crate) fn is_open() -> bool {
    OPEN.with_borrow(Option::is_some)
}

/// Asks the user whether to stop `request`'s process, in the windows' language; callable
/// from any thread, returns at once. A window still stopping one is brought to the front
/// instead; an idle one is replaced. Without the daemon's windows the request is only
/// logged.
pub fn ask_stop_original(request: StopOriginal) {
    if let Err(e) = slint::invoke_from_event_loop(move || open(request)) {
        tracing::info!(error = %e, "no windows: stopping the original is not offered");
    }
}

fn open(request: StopOriginal) {
    let Some(desktop) = windows::desktop() else {
        tracing::info!("no windows: stopping the original is not offered");
        return;
    };
    if let Some(open) = OPEN.with_borrow(Clone::clone) {
        if open.ui.get_busy() {
            select_desktop_language(desktop.locale.get());
            if let Err(e) = open.ui.show() {
                tracing::warn!(error = %e, "cannot show the window to stop the original");
            }
            foreground::take(&open.ui);
            return;
        }
        close(open.id);
    }
    if let Err(e) = create(&desktop, request) {
        tracing::error!(error = %e, "cannot show the window to stop the original");
    }
}

fn create(desktop: &Rc<Desktop>, request: StopOriginal) -> Result<(), PlatformError> {
    let ui = StopOriginalWindow::new()?;
    let locale = desktop.locale.get();
    select_desktop_language(locale);
    ui.set_question(question_text(&request, locale).into());
    let id = NEXT_ID.replace(NEXT_ID.get() + 1);
    let open = Rc::new(Open {
        id,
        ui: ui.clone_strong(),
        desktop: Rc::clone(desktop),
        request: Arc::new(request),
    });
    ui.on_stop(move || with(id, stop));
    ui.on_dismiss(move || {
        close_requested(id);
    });
    ui.window().on_close_requested(move || close_requested(id));
    OPEN.set(Some(open));
    if let Err(e) = ui.show() {
        OPEN.set(None);
        return Err(e);
    }
    foreground::take(&ui);
    Ok(())
}

/// «Отмена», «Закрыть» or the window's close button: closes the window `id`, unless it is
/// stopping the process, whose outcome the user must see.
fn close_requested(id: u64) -> CloseRequestResponse {
    worker::close_requested::<Open>(id, close)
}

fn close(id: u64) {
    let Some(open) = OPEN.with_borrow_mut(|slot| slot.take_if(|open| open.id == id)) else {
        return;
    };
    if let Err(e) = open.ui.hide() {
        tracing::warn!(error = %e, "cannot hide the window to stop the original");
    }
    // This may run inside one of the window's callbacks: release the window after it.
    slint::Timer::single_shot(Duration::ZERO, move || drop(open));
}

/// «Остановить»: stops the process on a worker thread, then shows how it went. Once it is
/// stopped, or there is nothing (left) to stop, only «Закрыть» is left.
fn stop(open: &Open) {
    let l = open.desktop.locale.get();
    show_message(&open.ui, Texts::of(l).stopping, false);
    let pid = open.request.pid;
    run(
        open,
        move |request| (request.stop)(l),
        move |desktop, open, result| {
            match &result {
                Ok(stopped) => tracing::info!(pid, ?stopped, "the original NCALayer is stopped"),
                Err(e) => tracing::warn!(pid, error = %e, "cannot stop the original NCALayer"),
            }
            let Some(open) = open else {
                return;
            };
            let (text, error) = outcome_text(&result, open.request.port, desktop.locale.get());
            show_message(&open.ui, &text, error);
            open.ui.set_done(finished(&result));
        },
    );
}

/// Whether trying again is pointless: stopped, or the process is gone, changed or not the
/// original.
fn finished(result: &io::Result<Stopped>) -> bool {
    match result {
        Ok(_) => true,
        Err(e) => matches!(
            e.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
        ),
    }
}

impl JobWindow for Open {
    type Services = StopOriginal;
    const NAME: &'static str = "stop-original";

    fn find(id: u64) -> Option<Rc<Open>> {
        current(id)
    }

    fn id(&self) -> u64 {
        self.id
    }

    fn desktop(&self) -> &Rc<Desktop> {
        &self.desktop
    }

    fn services(&self) -> Arc<StopOriginal> {
        Arc::clone(&self.request)
    }

    fn busy(&self) -> bool {
        self.ui.get_busy()
    }

    fn set_busy(&self, busy: bool) {
        self.ui.set_busy(busy);
    }

    fn show_message(&self, text: &str, error: bool) {
        show_message(&self.ui, text, error);
    }

    fn failure_text(&self) -> &'static str {
        Texts::of(self.desktop.locale.get()).cannot_start
    }
}

fn show_message(ui: &StopOriginalWindow, text: &str, error: bool) {
    ui.set_message(SharedString::from(text));
    ui.set_message_is_error(error);
}

/// The question about `request`'s process, in `l`.
fn question_text(request: &StopOriginal, l: Locale) -> String {
    Texts::of(l)
        .question
        .replace("{port}", &request.port.to_string())
        .replace("{exe}", &request.exe.display().to_string())
        .replace("{pid}", &request.pid.to_string())
}

/// What `result` of stopping the process holding `port` tells the user in `l`, and whether
/// it is a failure.
fn outcome_text(result: &io::Result<Stopped>, port: u16, l: Locale) -> (String, bool) {
    let t = Texts::of(l);
    match result {
        Ok(Stopped::Serving) => (t.serving.replace("{port}", &port.to_string()), false),
        Ok(Stopped::WssOff(why)) => (t.wss_off.replace("{0}", why), true),
        Err(e) => {
            let text = match e.kind() {
                io::ErrorKind::NotFound => t.gone.to_owned(),
                io::ErrorKind::InvalidInput => t.not_original.to_owned(),
                io::ErrorKind::PermissionDenied => t.denied.to_owned(),
                io::ErrorKind::TimedOut => t.timed_out.to_owned(),
                _ => format!("{}: {e}", t.failed),
            };
            (text, true)
        }
    }
}

/// The texts of the window, in one language.
struct Texts {
    /// `{port}`, `{exe}`, `{pid}`.
    question: &'static str,
    stopping: &'static str,
    /// `{port}`.
    serving: &'static str,
    /// `{0}`: why wss is off.
    wss_off: &'static str,
    gone: &'static str,
    not_original: &'static str,
    denied: &'static str,
    timed_out: &'static str,
    failed: &'static str,
    cannot_start: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                question: "{port} портын түпнұсқа NCALayer алып тұр. OpenNCALayer портты алуы үшін оны тоқтату керек пе?\n\nБағдарлама: {exe}\nПроцесс: {pid}\n\nТүпнұсқа сақталмай жабылады; оны кейін әдеттегідей қайта іске қосуға болады.",
                stopping: "Түпнұсқа тоқтатылуда…",
                serving: "Түпнұсқа тоқтатылды. OpenNCALayer сайттардың қосылуларын {port} портында қабылдайды.",
                wss_off: "Түпнұсқа тоқтатылды, бірақ OpenNCALayer портты ала алмады: {0}",
                gone: "Процесс аяқталып қойған немесе портты басқа процесс алған; ештеңе тоқтатылмады.",
                not_original: "Процесс түпнұсқа NCALayer-ге ұқсамайды, сондықтан ол тоқтатылмады.",
                denied: "Процесті тоқтатуға құқық жоқ (мүмкін, ол әкімші атынан іске қосылған).",
                timed_out: "Процесс белгіленген уақытта аяқталмады.",
                failed: "Түпнұсқаны тоқтату мүмкін болмады",
                cannot_start: "Әрекетті орындау мүмкін болмады",
            },
            Locale::Ru => &Texts {
                question: "Порт {port} занят оригинальным NCALayer. Остановить его, чтобы порт занял OpenNCALayer?\n\nПрограмма: {exe}\nПроцесс: {pid}\n\nОригинал будет завершён без сохранения; позже его можно запустить как обычно.",
                stopping: "Оригинал останавливается…",
                serving: "Оригинал остановлен. OpenNCALayer принимает подключения сайтов на порту {port}.",
                wss_off: "Оригинал остановлен, но OpenNCALayer не смог занять порт: {0}",
                gone: "Процесс уже завершился или порт занял другой процесс; ничего не остановлено.",
                not_original: "Процесс не похож на оригинальный NCALayer, поэтому он не остановлен.",
                denied: "Нет прав остановить процесс (возможно, он запущен от имени администратора).",
                timed_out: "Процесс не завершился за отведённое время.",
                failed: "Не удалось остановить оригинал",
                cannot_start: "Не удалось выполнить действие",
            },
            Locale::En => &Texts {
                question: "Port {port} is held by the original NCALayer. Stop it so that OpenNCALayer takes the port?\n\nProgram: {exe}\nProcess: {pid}\n\nThe original is ended without saving; it can be started again later as usual.",
                stopping: "Stopping the original…",
                serving: "The original is stopped. OpenNCALayer accepts the sites' connections on port {port}.",
                wss_off: "The original is stopped, but OpenNCALayer could not take the port: {0}",
                gone: "The process has ended already, or another one holds the port now; nothing was stopped.",
                not_original: "The process does not look like the original NCALayer, so it was not stopped.",
                denied: "No permission to stop the process (perhaps it runs as an administrator).",
                timed_out: "The process did not end in time.",
                failed: "Cannot stop the original",
                cannot_start: "Cannot carry out the action",
            },
        }
    }
}

/// The window on the offscreen platform of the tests, without an event loop: a job runs
/// when a test says ([`worker::manual`]).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings_view::fakes::{FakeOriginal, services};
    use crate::windows::{DesktopWindows, set_desktop_windows};
    use crate::{AboutInfo, offscreen};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn desktop(root: &std::path::Path) -> Rc<Desktop> {
        offscreen::install();
        worker::manual::enable();
        set_desktop_windows(DesktopWindows {
            locale: Locale::Ru,
            settings: services(root, FakeOriginal::default()),
            about: AboutInfo::default(),
            tls: crate::tls_wizard::fakes::services(root, Vec::new(), None),
            on_saved: Box::new(|_: &oncl_desktop::Settings| {}),
        });
        windows::desktop().unwrap()
    }

    fn the_window() -> Rc<Open> {
        OPEN.with_borrow(Clone::clone).expect("the window is open")
    }

    /// A request whose stop gives `outcomes` in turn; how often it ran.
    fn request(outcomes: Vec<io::Result<Stopped>>) -> (StopOriginal, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let outcomes = Mutex::new(outcomes.into_iter());
        let request = StopOriginal {
            port: 13579,
            exe: PathBuf::from(r"C:\Program Files\NCALayer\NCALayer.exe"),
            pid: 4242,
            stop: Box::new(move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                outcomes.lock().unwrap().next().expect("an outcome")
            }),
        };
        (request, calls)
    }

    #[test]
    fn asks_first_then_stops_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let _desktop = desktop(dir.path());
        let (request, calls) = request(vec![Ok(Stopped::Serving)]);
        open(request);
        let window = the_window();
        let question = window.ui.get_question();
        assert!(
            question.starts_with("Порт 13579 занят оригинальным NCALayer."),
            "{question}"
        );
        assert!(question.contains(r"Программа: C:\Program Files\NCALayer\NCALayer.exe"));
        assert!(question.contains("Процесс: 4242"));
        // Nothing is stopped by opening the window.
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!window.ui.get_busy() && !window.ui.get_done());

        window.ui.invoke_stop();
        assert!(window.ui.get_busy());
        assert_eq!(
            close_requested(window.id),
            CloseRequestResponse::KeepWindowShown
        );
        assert_eq!(worker::manual::run_all(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!window.ui.get_busy());
        assert!(window.ui.get_done());
        assert!(!window.ui.get_message_is_error());
        assert_eq!(
            window.ui.get_message(),
            "Оригинал остановлен. OpenNCALayer принимает подключения сайтов на порту 13579."
        );
        assert_eq!(close_requested(window.id), CloseRequestResponse::HideWindow);
        assert!(!is_open());
    }

    #[test]
    fn a_failure_is_shown_and_may_be_tried_again() {
        let dir = tempfile::tempdir().unwrap();
        let _desktop = desktop(dir.path());
        let (request, calls) = request(vec![
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            Ok(Stopped::WssOff("Порт 13579 занят".to_owned())),
        ]);
        open(request);
        let window = the_window();
        window.ui.invoke_stop();
        worker::manual::run_all();
        assert!(window.ui.get_message_is_error());
        assert!(window.ui.get_message().starts_with("Нет прав"));
        // Worth another try.
        assert!(!window.ui.get_done());

        window.ui.invoke_stop();
        worker::manual::run_all();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            window.ui.get_message(),
            "Оригинал остановлен, но OpenNCALayer не смог занять порт: Порт 13579 занят"
        );
        assert!(window.ui.get_message_is_error() && window.ui.get_done());
    }

    #[test]
    fn a_new_request_replaces_an_idle_window_only() {
        let dir = tempfile::tempdir().unwrap();
        let _desktop = desktop(dir.path());
        let (first, _) = request(vec![Ok(Stopped::Serving)]);
        open(first);
        let idle = the_window();
        let (second, _) = request(Vec::new());
        open(StopOriginal { pid: 7, ..second });
        let replaced = the_window();
        assert_ne!(replaced.id, idle.id);
        assert!(replaced.ui.get_question().contains("Процесс: 7"));

        replaced.ui.invoke_stop();
        let (third, _) = request(Vec::new());
        open(StopOriginal { pid: 8, ..third });
        assert_eq!(the_window().id, replaced.id, "a stopping window stays");
    }

    #[test]
    fn outcomes_in_every_language() {
        let failures = [
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Other,
        ];
        for l in [Locale::Ru, Locale::Kk, Locale::En] {
            let (serving, error) = outcome_text(&Ok(Stopped::Serving), 13600, l);
            assert!(serving.contains("13600") && !error, "{serving}");
            let texts: Vec<String> = failures
                .iter()
                .map(|&kind| {
                    let (text, error) = outcome_text(&Err(io::Error::new(kind, "boom")), 1, l);
                    assert!(error);
                    text
                })
                .collect();
            let mut distinct = texts.clone();
            distinct.sort();
            distinct.dedup();
            assert_eq!(distinct.len(), texts.len(), "{l:?}");
            // The detail of an unexpected error is kept.
            assert!(texts[4].ends_with(": boom"), "{}", texts[4]);
        }
        for (result, done) in [
            (Ok(Stopped::Serving), true),
            (Ok(Stopped::WssOff(String::new())), true),
            (Err(io::Error::from(io::ErrorKind::NotFound)), true),
            (Err(io::Error::from(io::ErrorKind::InvalidInput)), true),
            (Err(io::Error::from(io::ErrorKind::PermissionDenied)), false),
            (Err(io::Error::from(io::ErrorKind::TimedOut)), false),
        ] {
            assert_eq!(finished(&result), done, "{result:?}");
        }
    }
}
