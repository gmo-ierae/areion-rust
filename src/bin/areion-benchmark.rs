/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

use std::{array, fs::File, io::{self, Read}, os::fd::{AsRawFd, FromRawFd, RawFd}, process::exit, sync::OnceLock};

use perf_event_open_sys as sys;

fn perf_open(config: u32) -> File {
    let mut attrs = sys::bindings::perf_event_attr::default();
    attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
    attrs.type_ = sys::bindings::PERF_TYPE_HARDWARE;
    attrs.config = config as u64;
    attrs.set_exclude_kernel(1);
    attrs.set_exclude_hv(1);
    unsafe {
        let fd = sys::perf_event_open(&mut attrs, 0, -1, -1, 0);
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            println!("SYS_perf_event_open: {err:?}");
            println!("check '/proc/sys/kernel/perf_event_paranoid' <= 2");
            exit(1)
        }
        File::from_raw_fd(fd as RawFd)
    }
}

struct PerfFD {
    cycle_fd: File,
    instructions_fd: File
}

impl PerfFD {
    fn reset(self: &mut Self) {
        unsafe {
            sys::ioctls::RESET(self.cycle_fd.as_raw_fd(), 0);
            sys::ioctls::RESET(self.instructions_fd.as_raw_fd(), 0);    
        }
    }

    fn read(self: &mut Self) -> io::Result<(u64, u64)>{
        let mut buf: [u8; 8] = [0; 8];
        unsafe {
            self.cycle_fd.read_exact(&mut buf)?;
            let cycles = u64::from_ne_bytes(buf);
            self.instructions_fd.read_exact(&mut buf)?;
            let instructions = u64::from_ne_bytes(buf);
            Ok((cycles, instructions))
        }
    }
    
    fn report(self: &mut Self, function_name: &str, n_bytes: f64) {
        let (cycles, instructions) = self.read().unwrap();
        println!("{}, {}, {}", function_name, cycles as f64 / n_bytes, instructions as f64 / cycles as f64)
    }
    
    fn report_len(self: &mut Self, function_name: &str, len: usize, n_bytes: f64) {
        let (cycles, instructions) = self.read().unwrap();
        println!("{}({}), {}, {}", function_name, len, cycles as f64 / n_bytes, instructions as f64 / cycles as f64)
    }
}


const NUMBER_OF_LOOPS: u32 = 12500000;


fn benchmark_primitives(perf: &mut PerfFD) {
    {
        let mut input: [u8; 32] = array::from_fn(|i| i as u8);
        let mut output: [u8; 32] = [0; 32];
        perf.reset();
        let mut n_bytes: f64 = 0.0;
        for _i in 0..NUMBER_OF_LOOPS {
            unsafe {
                areion::permute_areion_256u8_x64_aesni(&mut output, &input);
                n_bytes += input.len() as f64;
                areion::permute_areion_256u8_x64_aesni(&mut input, &output);
                n_bytes += output.len() as f64;
            }            
        }
        perf.report("permute_areion_256u8", n_bytes)
    }
    {
        let mut input: [u8; 32] = array::from_fn(|i| i as u8);
        let mut output: [u8; 32] = [0; 32];
        perf.reset();
        let mut n_bytes: f64 = 0.0;
        for _i in 0..NUMBER_OF_LOOPS {
            unsafe {
                areion::inv_permute_areion_256u8_x64_aesni(&mut output, &input);
                n_bytes += input.len() as f64;
                areion::inv_permute_areion_256u8_x64_aesni(&mut input, &output);
                n_bytes += output.len() as f64;
            }            
        }
        perf.report("inv_permute_areion_256u8_x64_aesni", n_bytes)
    }
    {
        let mut input: [u8; 64] = array::from_fn(|i| i as u8);
        let mut output: [u8; 64] = [0; 64];
        perf.reset();
        let mut n_bytes: f64 = 0.0;
        for _i in 0..NUMBER_OF_LOOPS {
            unsafe {
                areion::permute_areion_512u8_x64_aesni(&mut output, &input);
                n_bytes += input.len() as f64;
                areion::permute_areion_512u8_x64_aesni(&mut input, &output);
                n_bytes += output.len() as f64;
            }            
        }
        perf.report("permute_areion_512u8_x64_aesni", n_bytes)
    }
    {
        let mut input: [u8; 64] = array::from_fn(|i| i as u8);
        let mut output: [u8; 64] = [0; 64];
        perf.reset();
        let mut n_bytes: f64 = 0.0;
        for _i in 0..NUMBER_OF_LOOPS {
            unsafe {
                areion::inv_permute_areion_512u8_x64_aesni(&mut output, &input);
                n_bytes += input.len() as f64;
                areion::inv_permute_areion_512u8_x64_aesni(&mut input, &output);
                n_bytes += output.len() as f64;
            }            
        }
        perf.report("inv_permute_areion_512u8_x64_aesni", n_bytes)
    }
}

fn benchmark_hashes(perf: &mut PerfFD) {
    {
        let mut input: [u8; 32] = array::from_fn(|i| i as u8);
        let mut output: [u8; 32] = [0; 32];
        perf.reset();
        let mut n_bytes: f64 = 0.0;
        for _i in 0..NUMBER_OF_LOOPS {
            unsafe {
                areion::areion_hash_dm_256(&mut output, &input);
                n_bytes += input.len() as f64;
                areion::areion_hash_dm_256(&mut input, &output);
                n_bytes += output.len() as f64;
            }            
        }
        perf.report("areion_hash_dm_256", n_bytes)
    }
    {
        let mut input: [u8; 64] = array::from_fn(|i| i as u8);
        let mut output: [u8; 64] = array::from_fn(|i| i as u8);
        perf.reset();
        let mut n_bytes: f64 = 0.0;
        for _i in 0..NUMBER_OF_LOOPS {
            unsafe {
                let mut buf: [u8; 32] = [0; 32];
                areion::areion_hash_dm_512(&mut buf, &input);
                output[0..32].copy_from_slice(&buf);
                n_bytes += input.len() as f64;
                areion::areion_hash_dm_512(&mut buf, &output);
                input[0..32].copy_from_slice(&buf);
                n_bytes += output.len() as f64;
            }            
        }
        perf.report("areion_hash_dm_512", n_bytes)
    }
    {
        let list = [
            16, 32, 48, 64, 80, 96, 112, 128, 256, 512, 1024, 2048, 4096
        ];
        for len in list {
            let mut input: [u8; 4096] = array::from_fn(|i| i as u8);
            let mut output: [u8; 4096] = array::from_fn(|i| i as u8);
            perf.reset();
            let mut n_bytes: f64 = 0.0;
            for _i in 0..NUMBER_OF_LOOPS {
                unsafe {
                    let mut buf: [u8; 32] = [0; 32];
                    areion::areion_hash_md(&mut buf, &input[0..len]);
                    output[0..32].copy_from_slice(&buf);
                    n_bytes += len as f64;
                    areion::areion_hash_md(&mut buf, &output[0..len]);
                    input[0..32].copy_from_slice(&buf);
                    n_bytes += len as f64;
                }            
            }
            perf.report_len("areion_hash_md", len, n_bytes)
    
        }
    }

}

fn benchmark_aead(perf: &mut PerfFD) {
    {
        let mut len = 32;
        while len < 4096 {
            let mut input: [u8; 2048] = array::from_fn(|i| i as u8);
            let mut output: [u8; 2048] = array::from_fn(|i| i as u8);
            let mut tag: [u8; 16] = [0; 16];
            let ad: [u8; 32] = array::from_fn(|i| i as u8);
            let nonce: [u8; 16] = array::from_fn(|i| i as u8);
            let key: [u8; 16] = array::from_fn(|i| i as u8);
            perf.reset();
            let mut n_bytes: f64 = 0.0;
            for _i in 0..NUMBER_OF_LOOPS {
                areion::encrypt_opp_256(&mut output[0..len], &mut tag, &ad, &input[0..len], &nonce, &key);
                n_bytes += len as f64;
                areion::encrypt_opp_256(&mut input[0..len], &mut tag, &ad, &output[0..len], &nonce, &key);
                n_bytes += len as f64;
            }
            perf.report_len("encrypt_opp_256", len, n_bytes);
            len *= 2;
        }
    }

}


fn main() {
    let mut perf = PerfFD {
        cycle_fd: perf_open(sys::bindings::PERF_COUNT_HW_CPU_CYCLES),
        instructions_fd: perf_open(sys::bindings::PERF_COUNT_HW_INSTRUCTIONS)
    };
    println!("function name: cycles per byte, instructions per cycle");
    benchmark_primitives(&mut perf);
    benchmark_hashes(&mut perf);
    benchmark_aead(&mut perf);
}
