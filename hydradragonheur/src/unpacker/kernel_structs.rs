use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Cursor;

pub struct Teb {
    pub seh_frame: u32,
    pub stack_base: u32,
    pub stack_limit: u32,
    pub sub_sys_tib: u32,
    pub fiber_data: u32,
    pub arbitrary_data: u32,
    pub addr_of_teb: u32,
    pub env_pointer: u32,
    pub process_id: u32,
    pub curr_thread_id: u32,
    pub act_rpc_handle: u32,
    pub addr_of_tls: u32,
    pub proc_env_block: u32,
}

impl Teb {
    pub fn new(
        stack_base: u32,
        stack_limit: u32,
        teb_base: u32,
        process_id: u32,
        thread_id: u32,
        peb_base: u32,
    ) -> Self {
        Self {
            seh_frame: 0xFFFFFFFF,
            stack_base,
            stack_limit,
            sub_sys_tib: 0,
            fiber_data: 0,
            arbitrary_data: 0,
            addr_of_teb: teb_base,
            env_pointer: 0,
            process_id,
            curr_thread_id: thread_id,
            act_rpc_handle: 0,
            addr_of_tls: 0,
            proc_env_block: peb_base,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(0x34);
        let mut w = Cursor::new(&mut buf);
        let _ = w.write_u32::<LittleEndian>(self.seh_frame);
        let _ = w.write_u32::<LittleEndian>(self.stack_base);
        let _ = w.write_u32::<LittleEndian>(self.stack_limit);
        let _ = w.write_u32::<LittleEndian>(self.sub_sys_tib);
        let _ = w.write_u32::<LittleEndian>(self.fiber_data);
        let _ = w.write_u32::<LittleEndian>(self.arbitrary_data);
        let _ = w.write_u32::<LittleEndian>(self.addr_of_teb);
        let _ = w.write_u32::<LittleEndian>(self.env_pointer);
        let _ = w.write_u32::<LittleEndian>(self.process_id);
        let _ = w.write_u32::<LittleEndian>(self.curr_thread_id);
        let _ = w.write_u32::<LittleEndian>(self.act_rpc_handle);
        let _ = w.write_u32::<LittleEndian>(self.addr_of_tls);
        let _ = w.write_u32::<LittleEndian>(self.proc_env_block);
        buf
    }
}

pub struct Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    pub mutant: u32,
    pub image_base_address: u32,
    pub ldr: u32,
}

impl Peb {
    pub fn new(image_base: u32, ldr_ptr: u32) -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            mutant: 0xFFFFFFFF,
            image_base_address: image_base,
            ldr: ldr_ptr,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(0x1C);
        let mut w = Cursor::new(&mut buf);
        let _ = w.write_u8(self.inherited_address_space);
        let _ = w.write_u8(self.read_image_file_exec_options);
        let _ = w.write_u8(self.being_debugged);
        let _ = w.write_u8(self.bit_field);
        let _ = w.write_u32::<LittleEndian>(self.mutant);
        let _ = w.write_u32::<LittleEndian>(self.image_base_address);
        let _ = w.write_u32::<LittleEndian>(self.ldr);
        buf
    }
}

pub struct PebLdrData {
    pub length: u32,
    pub initialized: u32,
    pub ss_handle: u32,
    pub in_load_order_first: u32,
    pub in_load_order_last: u32,
    pub in_memory_order_first: u32,
    pub in_memory_order_last: u32,
    pub in_init_order_first: u32,
    pub in_init_order_last: u32,
}

impl PebLdrData {
    pub fn new(list_entry_base: u32) -> Self {
        Self {
            length: 0x30,
            initialized: 1,
            ss_handle: 0,
            in_load_order_first: list_entry_base,
            in_load_order_last: list_entry_base + 24,
            in_memory_order_first: list_entry_base,
            in_memory_order_last: list_entry_base + 24,
            in_init_order_first: list_entry_base,
            in_init_order_last: list_entry_base + 24,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(0x30);
        let mut w = Cursor::new(&mut buf);
        let _ = w.write_u32::<LittleEndian>(self.length);
        let _ = w.write_u32::<LittleEndian>(self.initialized);
        let _ = w.write_u32::<LittleEndian>(self.ss_handle);
        let _ = w.write_u32::<LittleEndian>(self.in_load_order_first);
        let _ = w.write_u32::<LittleEndian>(self.in_load_order_last);
        let _ = w.write_u32::<LittleEndian>(self.in_memory_order_first);
        let _ = w.write_u32::<LittleEndian>(self.in_memory_order_last);
        let _ = w.write_u32::<LittleEndian>(self.in_init_order_first);
        let _ = w.write_u32::<LittleEndian>(self.in_init_order_last);
        buf
    }
}

pub struct ListEntry {
    pub next: u32,
    pub prev: u32,
    pub value: u32,
}

impl ListEntry {
    pub fn new(next: u32, prev: u32, value: u32) -> Self {
        Self { next, prev, value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        let mut w = Cursor::new(&mut buf);
        let _ = w.write_u32::<LittleEndian>(self.next);
        let _ = w.write_u32::<LittleEndian>(self.prev);
        let _ = w.write_u32::<LittleEndian>(self.value);
        buf
    }
}

pub struct FileTime {
    pub dw_low_date_time: u32,
    pub dw_high_date_time: u32,
}

impl FileTime {
    pub fn new(dw_low_date_time: u32, dw_high_date_time: u32) -> Self {
        Self {
            dw_low_date_time,
            dw_high_date_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        let mut w = Cursor::new(&mut buf);
        let _ = w.write_u32::<LittleEndian>(self.dw_low_date_time);
        let _ = w.write_u32::<LittleEndian>(self.dw_high_date_time);
        buf
    }
}
