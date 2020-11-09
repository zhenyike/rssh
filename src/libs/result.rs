use std::error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct MyErr {
    pub msg: String,
}

impl fmt::Display for MyErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl error::Error for MyErr {
    fn description(&self) -> &str {
        &self.msg
    }
}

