use super::my_crypto::my_crypto;
use super::params;
use super::result;

use rustc_serialize::json;

use std::fs::File;
use std::io::prelude::*;
use std::io::{BufRead, BufReader};

use crate::libs::result::MyErr;
use libc::c_char;
use libc::c_int;
use libc::c_ulong;
use std::ffi::CStr;
use std::ffi::CString;

#[repr(C)]
struct CRe {
    re_size: c_int,
    re_value: *mut c_char,
}

#[link(name = "fillfile", kind = "static")]
extern "C" {
    // 由于正在运行的可执行文件不可写, 所有写入操作都会生成到 ${file_name}.bak 文件, 需要手动替换
    // 初始化文件, 填充指定大小个 0, 添加 file_tail
    fn init_file(file_name: *const c_char, data: *const c_char, size: c_ulong, pos: c_int)
        -> c_int;

    // 读取 json -> aes -> base64
    fn read_info(file_name: *const c_char) -> CRe;

    // 写入 json -> aes -> base64
    fn write_info(file_name: *const c_char, c_json: *mut c_char) -> c_int;
}

/* 读取 json 字符串 */
fn read_json(file_name: &str) -> Result<String, result::MyErr> {
    let (c_size, c_buff) = unsafe {
        let file = CString::new(file_name).unwrap();
        let c_ptr = read_info(file.as_ptr() as *const i8);

        let c_buf = CStr::from_ptr(c_ptr.re_value as *const i8);
        (c_ptr.re_size, c_buf)
    };
    let hash_info = match c_size {
        0 => String::from(""),
        _ => c_buff.to_string_lossy().into_owned(),
    };

    my_crypto(&hash_info, false)
}

/* 写入 json 字符串 */
fn write_json(file_name: &str, content: &str) -> Result<(), result::MyErr> {
    let info = match my_crypto(content, true) {
        Ok(i) => i,
        Err(e) => return Err(e),
    };
    let re = unsafe {
        let file = CString::new(file_name).unwrap();
        let con = CString::new(info).unwrap();
        write_info(file.as_ptr() as *const i8, con.as_ptr() as *mut i8)
    };

    return match re {
        0 => {
            // 成功则替换旧文件
            let new_file = format!("{}.bak", file_name);
            std::fs::rename(new_file, file_name).expect("替换旧文件失败");
            Ok(())
        }
        _ => {
            // 失败则删除生成的 .bak
            match std::fs::remove_file(format!("{}.bak", file_name)) {
                Ok(()) => {}
                Err(_) => {}
            };
            Err(result::MyErr {
                msg: String::from("更新 rdata 失败!"),
            })
        }
    };
}

// 用户 -> 密码
#[derive(RustcDecodable, RustcEncodable, Debug)]
struct UserInfo {
    username: String,
    password: String,
}

// IP -> [用户 -> 密码]
#[derive(RustcDecodable, RustcEncodable, Debug)]
struct HostInfo {
    ip: String,
    users: Vec<UserInfo>,
}

// IP缩写 -> 序号
#[derive(RustcDecodable, RustcEncodable, Debug)]
struct LastChoose {
    ip: String,
    index: usize,
}

#[derive(RustcDecodable, RustcEncodable, Debug)]
pub struct Rdata {
    current: Vec<LastChoose>,
    hosts: Vec<HostInfo>,
    pub pwd: String,
    pub version: u8,
}

impl Rdata {
    /* 从文件读取 rdata */
    pub fn get(file_name: &str) -> Result<Rdata, result::MyErr> {
        let json_data = match read_json(&file_name) {
            Ok(j) => j,
            Err(e) => return Err(e),
        };
        let a: Rdata = match json::decode(&json_data) {
            Ok(e) => e,
            Err(_) => {
                return Err(MyErr {
                    msg: String::from("json解码出错"),
                })
            }
        };
        Ok(a)
    }

    /* 初始化文件 */
    pub fn init(file_name: &str, pwd: &str, version: u8) -> Result<(), result::MyErr> {
        let rdata = Rdata {
            current: vec![],
            hosts: vec![],
            pwd: String::from(pwd),
            version,
        };

        let pos = match self::Rdata::get(&file_name) {
            Ok(_) => 1,
            Err(_) => 0,
        };
        let json_info = json::encode(&rdata).unwrap();
        let hash_info = my_crypto(&json_info, true).unwrap();

        let re = unsafe {
            let file = CString::new(file_name).unwrap();
            let info = CString::new(hash_info).unwrap();
            init_file(
                file.as_ptr() as *const i8,
                info.as_ptr() as *const i8,
                20,
                pos,
            )
        };

        return match re {
            0 => {
                // 成功则替换旧文件
                let new_file = format!("{}.bak", file_name);
                std::fs::rename(new_file, file_name).expect("替换旧文件失败");
                Ok(())
            }
            _ => {
                // 失败则删除生成的 .bak
                match std::fs::remove_file(format!("{}.bak", file_name)) {
                    Ok(()) => {}
                    Err(_) => {}
                };
                Err(result::MyErr {
                    msg: String::from("初始化文件失败!"),
                })
            }
        };
    }

    /* 从文件导入密码 */
    pub fn import_pwd(
        mut self,
        file_name: &str,
        params: &params::Params,
    ) -> Result<(), result::MyErr> {
        let file = match File::open(&file_name) {
            Ok(f) => f,
            Err(_e) => {
                return Err(result::MyErr {
                    msg: format!("打开文件: {} 失败", &file_name),
                })
            }
        };

        let file = BufReader::new(file);
        for line in file.lines() {
            let str_temp = match line {
                Ok(s) => s,
                Err(e) => return Err(result::MyErr { msg: e.to_string() }),
            };
            let ip_user: Vec<&str> = str_temp.split(" ").collect();
            if ip_user.len() < 3 {
                return Err(result::MyErr {
                    msg: String::from("格式错误"),
                });
            }
            set_password(&mut self, ip_user[0], ip_user[1], ip_user[2]);
        }

        self.save(&params.file_path)
    }

    /* 导出密码 */
    pub fn export_pwd(&self, file_name: &str) -> Result<(), result::MyErr> {
        let mut f = match File::create(file_name) {
            Ok(f) => f,
            Err(_e) => {
                return Err(result::MyErr {
                    msg: format!("创建文件 {} 失败", &file_name),
                })
            }
        };

        for host in &self.hosts {
            for user in &host.users {
                writeln!(f, "{} {} {}", &host.ip, &user.username, &user.password).unwrap();
            }
        }
        Ok(())
    }

    /* 保存到文件 */
    pub fn save(&self, file_name: &str) -> Result<(), result::MyErr> {
        let json_data = match json::encode(&self) {
            Ok(j) => j,
            Err(_) => {
                return Err(MyErr {
                    msg: String::from("json编码出错"),
                })
            }
        };
        write_json(file_name, &json_data)
    }

    /* 删除密码 */
    pub fn delete_pwd(&mut self, params: &params::Params) -> Result<(), result::MyErr> {
        let (x, y) = get_password(&self, &params.ip, &params.user);

        if x != -1 && y != -1 {
            match &self.hosts[x as usize].users.len() {
                1 => {
                    &self.hosts.remove(x as usize);
                }
                _ => {
                    &self.hosts[x as usize].users.remove(y as usize);
                }
            }
        }
        //save_to_file(&params.file_path, &rdata)
        self.save(&params.file_path)
    }

    /* 列出指定 ip 所有用户 */
    pub fn get_user(&self, ip: &str) -> Result<(), result::MyErr> {
        for host in &self.hosts {
            if &host.ip == ip {
                for u in &host.users {
                    println!("{} ", u.username);
                }
            }
        }
        Ok(())
    }
}

pub struct Pwd {
    pub ip: String,
    pub user: String,
    pub password: String,
}
impl Pwd {
    // 获取密码
    pub fn get_pwd(
        password_info: &mut Rdata,
        params: &params::Params,
    ) -> Result<Pwd, result::MyErr> {
        let (i, j) = get_password(&password_info, &params.ip, &params.user);
        if i == -1 || j == -1 {
            let re = get_password_fuzzy(&password_info, &params.ip, &params.user);
            match re.len() {
                0 => {
                    return Err(result::MyErr {
                        msg: String::from("not found"),
                    })
                }
                1 => {
                    let (i, j) = re[0];

                    return Ok(Pwd {
                        ip: password_info.hosts[i as usize].ip.clone(),
                        user: password_info.hosts[i as usize].users[j as usize]
                            .username
                            .clone(),
                        password: password_info.hosts[i as usize].users[j as usize]
                            .password
                            .clone(),
                    });
                }
                _ => {
                    // 缓存到 vector 用于排序
                    let mut temp_str: Vec<String> = Vec::new();
                    for r in &re {
                        let (i, j) = *r;
                        temp_str.push(format!(
                            "{} {} {}",
                            &password_info.hosts[i as usize].ip,
                            &password_info.hosts[i as usize].users[j as usize].username,
                            password_info.hosts[i as usize].users[j as usize].password
                        ));
                    }
                    temp_str.sort();

                    println!("找到多个符合条件的 IP: ");
                    let mut idx = 1;
                    for r in &temp_str {
                        println!("    {}. {}", idx, &r[..r.find(' ').unwrap()]);
                        idx += 1;
                    }

                    let mut old_idx: usize = 0;
                    let mut last_index: usize = 0;
                    for x in &password_info.current {
                        if x.ip == params.ip {
                            old_idx = x.index;
                            break;
                        }
                        last_index += 1;
                    }
                    if old_idx != 0 && old_idx <= temp_str.len() {
                        // 存在默认选项, 且数值正确
                        print!("请选择 [{}]: ", old_idx);
                    } else {
                        print!("请选择: ");
                    }
                    std::io::stdout().flush().unwrap();

                    // 读取用户输入
                    let mut cho = String::new();
                    match std::io::stdin().read_line(&mut cho) {
                        Ok(_n) => {}
                        Err(_err) => {
                            return Err(result::MyErr {
                                msg: String::from("err choose"),
                            })
                        }
                    }

                    //let mut choose: usize = 0;
                    let choose: usize;
                    if old_idx != 0 && &cho == "\n" {
                        choose = old_idx;
                    } else {
                        // 字符串转数字
                        choose = match cho.trim().parse() {
                            Ok(n) => n,
                            Err(_err) => {
                                return Err(result::MyErr {
                                    msg: String::from("err choose"),
                                })
                            }
                        };
                    }

                    // 验证输入
                    if choose > temp_str.len() || choose <= 0 {
                        return Err(result::MyErr {
                            msg: String::from("err choose"),
                        });
                    }

                    // 更新配置文件
                    if old_idx > 0 && choose != old_idx {
                        // 配置文件中存在，但不相等
                        password_info.current[last_index].index = choose;
                        password_info.save(&params.file_path).unwrap();
                    } else if old_idx <= 0 {
                        // 配置文件中不存在
                        password_info.current.push(LastChoose {
                            ip: params.ip.clone(),
                            index: choose,
                        });
                        password_info.save(&params.file_path).unwrap();
                    }

                    let re: Vec<&str> = temp_str[choose - 1].split(" ").collect();
                    // 返回结果
                    return Ok(Pwd {
                        ip: re[0].to_string(),
                        user: re[1].to_string(),
                        password: re[2].to_string(),
                    });
                }
            }
        } else {
            return Ok(Pwd {
                ip: password_info.hosts[i as usize].ip.clone(),
                user: password_info.hosts[i as usize].users[j as usize]
                    .username
                    .clone(),
                password: password_info.hosts[i as usize].users[j as usize]
                    .password
                    .clone(),
            });
        }
    }

    // 更改密码, 有则更新, 没有则添加
    pub fn change_password(data: &mut Rdata, params: &params::Params) -> Result<(), MyErr> {
        set_password(data, &params.ip, &params.user, &params.password);
        // 保存
        data.save(&params.file_path)
    }
}

// 查找用户密码
fn get_password(data: &Rdata, ip: &str, user: &str) -> (i32, i32) {
    for i in 0..data.hosts.len() {
        if ip == data.hosts[i].ip {
            for j in 0..data.hosts[i].users.len() {
                if user == data.hosts[i].users[j].username {
                    return (i as i32, j as i32);
                }
            }
            return (i as i32, -1);
        }
    }
    (-1, -1)
}

// 模糊 ip 查找
fn get_password_fuzzy(data: &Rdata, ip: &str, user: &str) -> Vec<(i32, i32)> {
    let mut re: Vec<(i32, i32)> = Vec::new();

    for i in 0..data.hosts.len() {
        // 匹配到 ip
        if data.hosts[i].ip.find(ip) >= Some(0) {
            for j in 0..data.hosts[i].users.len() {
                // 匹配到用户
                if user == data.hosts[i].users[j].username {
                    re.push((i as i32, j as i32));
                }
            }
        }
    }
    re
}

// 更新或新增密码
fn set_password(data: &mut Rdata, ip: &str, user: &str, password: &str) {
    let (i, j) = get_password(data, ip, user);

    if i == -1 {
        data.hosts.push(HostInfo {
            ip: ip.to_string(),
            users: vec![UserInfo {
                username: user.to_string(),
                password: password.to_string(),
            }],
        });
    } else {
        if j == -1 {
            data.hosts[i as usize].users.push(UserInfo {
                username: user.to_string(),
                password: password.to_string(),
            });
        } else {
            data.hosts[i as usize].users[j as usize].password = password.to_string();
        }
    }
}

