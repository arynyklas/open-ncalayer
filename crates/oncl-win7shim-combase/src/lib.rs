//! `combase.dll` for the Windows 7 builds of OpenNCALayer, shipped next to the executables.
//!
//! The `windows` crates import `CoTaskMemFree` and `CoCreateFreeThreadedMarshaler` from
//! `combase.dll`, which Windows 7 does not have; Windows 7 has both in `ole32.dll`. This DLL
//! exports exactly these names as forwards to `ole32.dll` (`combase.def`, linked by
//! `build.rs`) and has no code of its own.
//!
//! Windows 8 and later never load it: there `combase.dll` is a known DLL, and the loader maps
//! the system one for every import of that name.
