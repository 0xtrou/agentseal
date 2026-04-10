include!(concat!(env!("OUT_DIR"), "/launcher_markers.rs"));

#[inline(never)]
pub fn preserve_launcher_markers() -> *const LauncherMarkers {
    let ptr = core::ptr::addr_of!(LAUNCHER_MARKERS);
    unsafe {
        core::ptr::read_volatile(ptr);
    }
    ptr
}

#[cfg(test)]
mod tests {
    #[test]
    fn preserve_launcher_markers_returns_static_address() {
        let ptr = super::preserve_launcher_markers();
        assert_eq!(ptr, core::ptr::addr_of!(super::LAUNCHER_MARKERS));
    }
}
