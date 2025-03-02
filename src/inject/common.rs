use sysinfo::System;

pub fn get_process_id_by_name(name: &str) -> Option<i32> {
    let mut system = System::new_all();
    system.refresh_all();
    for (_, process) in system.processes() {
        if process.name() == name {
            return Some(process.pid().as_u32() as i32);
        }
    }
    None
}
