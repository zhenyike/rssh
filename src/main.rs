mod libs;
use libs::params;
use libs::rdata;
use libs::ssh;

use std::io::prelude::*;

use rpassword::read_password;

fn main() {
    // 二进制文件 路径
    let path_buf = std::env::current_exe().unwrap();
    let path = path_buf.into_os_string().into_string().unwrap();

    // 命令行参数解析
    let params = match params::Params::parse(&mut std::env::args(), path) {
        Ok(p) => p,
        Err(e) => {
            params::Params::help(&e.msg);
            return;
        }
    };

    /* 初始化 */
    if params.option == 'f' {
        if verify("init") {
            match rdata::Rdata::init(&params.file_path, &params.pwd, params.version) {
                Ok(()) => {}
                Err(e) => println!("{}", e.msg),
            }
        } else {
            println!("密码错误");
        }
        return;
    }

    let mut rdata = match rdata::Rdata::get(&params.file_path) {
        Ok(r) => r,
        Err(_) => {
            println!("请先使用 -f 选项执行初始化");
            return;
        }
    };

    match params.option {
        'c' => {
            // 非特权：修改密码
            if rdata.version > 0 {
                if !verify(&rdata.pwd) {
                    println!("密码错误");
                    return;
                }
            }
            match rdata::Pwd::change_password(&mut rdata, &params) {
                Ok(()) => {}
                Err(e) => println!("{}", e.msg),
            }
        }
        'l' => {
            // 特权：批量导入
            if verify(&rdata.pwd) {
                match rdata.import_pwd(&params.in_file, &params) {
                    Ok(()) => {}
                    Err(e) => println!("{}", e.msg),
                };
            } else {
                println!("口令错误");
            }
        }
        'e' => {
            // 特权：导出用户密码
            if verify(&rdata.pwd) {
                match rdata.export_pwd(&params.in_file) {
                    Ok(()) => {}
                    Err(e) => println!("{}", e.msg),
                };
            } else {
                println!("口令错误");
            }
        }
        'g' => {
            // 半特权：获取密码
            let pwd = match rdata::Pwd::get_pwd(&mut rdata, &params) {
                Ok(p) => p,
                Err(e) => {
                    println!("{}", e.msg);
                    std::process::exit(1);
                }
            };

            if &params.key == "yikeyike" {
                // 用户其他程序调用, 密码没有空格，因此空格做分隔符
                println!("{} {} {}", pwd.user, pwd.ip, pwd.password);
            } else if verify(&rdata.pwd) {
                println!("{}@{}\n{}", pwd.user, pwd.ip, pwd.password);
            }
        }
        'r' => {
            // 非特权：运行指定命令
            let pwd = match rdata::Pwd::get_pwd(&mut rdata, &params) {
                Ok(p) => p,
                Err(e) => {
                    println!("{}", e.msg);
                    std::process::exit(1);
                }
            };
            let ip_user = format!("{}@{}", pwd.user, pwd.ip);
            if true {
                match ssh::ssh(&ip_user, &pwd.password, &params.cmd) {
                    Ok(()) => {}
                    Err(_) => {
                        std::process::exit(1);
                    }
                };
            }
        }
        'd' => {
            // 特权：删除指定用户
            if verify(&rdata.pwd) {
                match rdata.delete_pwd(&params) {
                    Ok(()) => println!("已删除"),
                    Err(e) => println!("删除失败: {}", e.msg),
                }
            } else {
                println!("密码错误");
            }
            return;
        }
        'p' => {
            // 非特权：列出指定ip所有用户
            if rdata.version == 1 && !verify(&rdata.pwd) {
                println!("密码错误");
                return;
            }
            rdata.get_user(&params.ip).unwrap();
        }
        'k' => {
            // 特权：修改验证密码
            if verify(&rdata.pwd) {
                rdata.pwd = params.pwd;
                rdata.version = params.version;
                rdata.save(&params.file_path).unwrap();
            } else {
                println!("密码错误");
            }
        }
        _ => {
            // 非特权：登录
            let pwd = match rdata::Pwd::get_pwd(&mut rdata, &params) {
                Ok(p) => p,
                Err(e) => {
                    println!("{}", e.msg);
                    return;
                }
            };

            let ip_user = format!("{}@{}", pwd.user, pwd.ip);

            // version = 1, 验证密码
            if rdata.version == 1 && !verify(&rdata.pwd) {
                println!("密码错误");
                return;
            }
            if true {
                println!("ssh {}", &ip_user);
                match ssh::ssh(&ip_user, &pwd.password, "") {
                    Ok(()) => {}
                    Err(_) => {} // 不打印错误信息, 子进程执行的任何语句报错都会捕获
                };
            }
        }
    }
}

/* 验证口令 */
fn verify(key: &str) -> bool {
    print!("请输入密码: ");
    std::io::stdout().flush().unwrap();

    if let Ok(n) = read_password() {
        if &n == key {
            return true;
        }
    };
    false
}

