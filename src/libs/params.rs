use super::result;
use std::env::Args;

#[derive(Debug)]
pub struct Params {
    pub option: char,      // 选项
    pub ip: String,        // ip
    pub user: String,      // 用户
    pub password: String,  // 密码
    pub in_file: String,   // 导入导出文件
    pub key: String,       // 认证口令
    pub cmd: String,       // 远程执行命令
    pub file_path: String, // 二进制文件路径
    pub pwd: String,       // 执行该程序时需要输入的密码
    pub version: u8,       // 1: 所有命令均需要输入密码, 0: 特权命令才需要密码
}

impl Params {
    pub fn parse(args: &mut Args, data_file: String) -> Result<Params, result::MyErr> {
        // rssh 192.168.137.220                     // 默认用户 root 登录
        // rssh 192.168.137.220 root                // 指定用户登录
        // rssh -f pwd version                      // 初始化, 复制源文件, 填充到指定大小, 初始化密码
        //                                                version 1: 所有命令均需要输入密码, 0: 特权命令才需要密码
        // rssh -k pwd version                      // 修改认证密码
        // rssh -c 192.168.137.220 root yike        // 修改密码
        // rssh -l /root/password.txt               // 批量导入密码
        // rssh -e /root/password.txt               // 批量导出密码
        // rssh -g 192.168.137.220 root             // 获取指定密码
        // rssh -r 192.168.137.220 root 'ls -l'     // 运行命令

        // rssh -d 192.168.137.220 root             // 删除用户
        // rssh -v                                  // 验证密码正确性
        // rssh -p 192.168.137.200                  // 列出指定 ip 所有用户

        let exe_name = args.next().unwrap();

        if args.len() < 1 {
            Err(result::MyErr { msg: exe_name })
        } else {
            let mut params = Params {
                option: ' ',
                ip: String::from(""),
                user: String::from("root"),
                password: String::from(""),
                in_file: String::from(""),
                key: String::from(""),
                cmd: String::from(""),
                file_path: data_file,
                pwd: String::from("init"),
                version: 0,
            };

            let temp = args.next().unwrap();

            if &temp == "-c" {
                // 修改添加密码
                params.option = 'c';
                if args.len() < 3 {
                    return Err(result::MyErr { msg: exe_name });
                }
                params.ip = args.next().unwrap();
                params.user = args.next().unwrap();
                params.password = args.next().unwrap();
            } else if &temp == "-l" {
                // 导入密码
                params.option = 'l';
                match args.next() {
                    Some(f) => params.in_file = f,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
            } else if &temp == "-e" {
                // 导出密码
                params.option = 'e';
                match args.next() {
                    Some(f) => params.in_file = f,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
            } else if &temp == "-g" {
                // 获取密码
                params.option = 'g';

                match args.next() {
                    Some(p) => params.ip = p,
                    None => return Err(result::MyErr { msg: exe_name }),
                }

                match args.next() {
                    Some(u) => params.user = u,
                    None => {}
                }

                match args.next() {
                    Some(k) => params.key = k,
                    None => {}
                }
            } else if &temp == "-f" {
                // 初始化源文件
                params.option = 'f';
                match args.next() {
                    Some(p) => params.pwd = p,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
                match args.next() {
                    Some(n) => match n.parse() {
                        Ok(p) => params.version = p,
                        Err(_) => return Err(result::MyErr { msg: exe_name }),
                    },
                    None => return Err(result::MyErr { msg: exe_name }),
                }
            } else if &temp == "-r" {
                // 运行命令
                params.option = 'r';
                match args.next() {
                    Some(p) => params.ip = p,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
                match args.next() {
                    Some(u) => params.user = u,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
                match args.next() {
                    Some(c) => params.cmd = c,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
            } else if &temp == "-k" {
                // 修改用户认证口令
                params.option = 'k';
                match args.next() {
                    Some(p) => params.pwd = p,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
                match args.next() {
                    Some(n) => match n.parse() {
                        Ok(p) => params.version = p,
                        Err(_) => return Err(result::MyErr { msg: exe_name }),
                    },
                    None => return Err(result::MyErr { msg: exe_name }),
                }
            } else if &temp == "-d" {
                // 删除用户密码
                params.option = 'd';
                match args.next() {
                    Some(p) => params.ip = p,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
                match args.next() {
                    Some(u) => params.user = u,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
            } else if &temp == "-v" {
                params.option = 'v';
            } else if &temp == "-p" {
                // 列出指定 ip 的用户
                params.option = 'p';
                match args.next() {
                    Some(p) => params.ip = p,
                    None => return Err(result::MyErr { msg: exe_name }),
                }
            } else {
                // 登录
                params.ip = temp;
                match args.next() {
                    Some(u) => params.user = u,
                    None => {}
                }
            };
            Ok(params)
        }
    }

    pub fn help(exe_name: &str) {
        println!("使用说明: ");
        println!("  {} ip [user]        远程连接, 默认用户 root", &exe_name);
        println!("  {} -c ip user pwd   修改或新增密码", &exe_name);
        println!("  {} -r ip user cmd   执行命令", &exe_name);
        println!(
            "  {} -l file_name     导入用户密码, 格式: ip user pwd",
            &exe_name
        );
        println!("  {} -e file_name     导出用户密码导文件", &exe_name);
        println!("  {} -g ip [user]     获取密码", &exe_name);
        println!("  {} -f pwd flag      初始化, pwd: 执行本程序所需密码; flag: 0 特权操作才需密码, 1 所有操作都需密码", &exe_name);
        println!("  {} -k pwd flag      修改认证密码", &exe_name);
        println!("  {} -d ip user       删除密码", &exe_name);
        //println!("  {} -v               验证密码", &exe_name);
        println!("  {} -p ip            列出所有用户", &exe_name);
    }
}


