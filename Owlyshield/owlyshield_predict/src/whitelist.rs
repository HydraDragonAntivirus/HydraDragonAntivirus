use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{io, thread, time};

#[derive(Debug)]
pub struct WhiteList {
    // Key: AppName, Value: Optional Required Signer Name
    whitelist: Arc<Mutex<HashMap<String, Option<String>>>>,
    path: Arc<PathBuf>,
}

impl WhiteList {
    pub fn from(path: &Path) -> Result<WhiteList, std::io::Error> {
        let mut whitelist = HashMap::new();
        let lines = Self::load(path)?;
        for l in lines {
            if let Ok(line) = l {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() > 1 {
                    whitelist.insert(parts[0].to_string(), Some(parts[1].trim().to_string()));
                } else {
                    whitelist.insert(line.trim().to_string(), None);
                }
            }
        }
        let res = WhiteList {
            whitelist: Arc::new(Mutex::new(whitelist)),
            path: Arc::new(PathBuf::from(path)),
        };
        Ok(res)
    }

    /// Returns the required signer if the app is whitelisted.
    /// Returns None if the app is not in the whitelist.
    /// Returns Some(None) if whitelisted with NO specific signer requirement (Any Trusted).
    /// Returns Some(Some("Name")) if whitelisted with a specific signer requirement.
    pub fn get_required_signer(&self, appname: &str) -> Option<Option<String>> {
        self.whitelist.lock().unwrap().get(appname).cloned()
    }

    pub fn refresh_periodically(&self) {
        let whitelist_bis = Arc::clone(&self.whitelist);
        let path_bis = Arc::clone(&self.path);
        thread::spawn(move || loop {
            let res_lines = Self::load(&path_bis);
            {
                let mut set_whitelist = whitelist_bis.lock().unwrap();
                if let Ok(lines) = res_lines {
                    set_whitelist.clear();
                    for l in lines {
                        if let Ok(line) = l {
                            let parts: Vec<&str> = line.split('|').collect();
                            if parts.len() > 1 {
                                set_whitelist.insert(parts[0].to_string(), Some(parts[1].trim().to_string()));
                            } else {
                                set_whitelist.insert(line.trim().to_string(), None);
                            }
                        }
                    }
                }
            }
            thread::sleep(time::Duration::from_secs(10));
        });
    }

    fn load(path: &Path) -> Result<io::Lines<io::BufReader<File>>, std::io::Error> {
        let file = File::open(path)?;
        let lines = io::BufReader::new(file).lines();
        Ok(lines)
    }
}
