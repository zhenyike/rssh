use libc::c_char;
use libc::c_int;
use std::ffi::CString;

use super::result;

#[link(name = "sshpass", kind = "static")]
extern "C" {
    fn run_main(ip_user: *const c_char, password: *const c_char, cmd: *const c_char) -> c_int;
}

pub fn ssh(ip_user: &str, password: &str, cmd: &str) -> Result<(), result::MyErr> {
    let re;
    unsafe {
        let c_ip_user = CString::new(ip_user).unwrap();
        let c_password = CString::new(password).unwrap();
        let c_cmd = CString::new(cmd).unwrap();

        re = run_main(
            c_ip_user.as_ptr() as *const i8,
            c_password.as_ptr() as *const i8,
            c_cmd.as_ptr() as *const i8,
        );
    }

    match re {
        0 => Ok(()),
        1 => Err( result::MyErr{
            msg: String::from("参数错误")
        }),
        2=> Err(result::MyErr{
            msg: String::from("参数冲突")
        }),
        3 => Err( result::MyErr {
            msg: String::from("运行时错误")
        }),
        4 => Err(result::MyErr {
            msg: String::from("解析错误")
        }),
        5 => Err(result::MyErr {
            msg: String::from("密码错误"),
        }),
        6=> Err(result::MyErr {
            msg: String::from("主机Key未知")
        }),
        7=>Err(result::MyErr{
            msg: String::from("主机Key已改变")
        }),
        255 => Err(result::MyErr {
            msg: String::from("连接超时"),
        }),
        _ => Err(result::MyErr {
            msg: String::from("内部错误"),
        }),
    }
}

