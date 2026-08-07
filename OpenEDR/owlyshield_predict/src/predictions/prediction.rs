//! Behavioral feature-tracking data structures.
//! No ML inference — pure data containers used by the behavior engine.

pub mod input_tensors {
    use crate::process::ProcessRecord;
    use serde::{Deserialize, Serialize};
    use std::ops::Index;

    /// A 2-D matrix with a capped number of rows, stored as a Vec of Vecs.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct VecvecCapped<T> {
        cap: usize,
        col_size: usize,
        data: std::collections::VecDeque<Vec<T>>,
    }

    impl<T: Clone + Default> VecvecCapped<T> {
        pub fn new(cap: usize, col_size: usize) -> Self {
            VecvecCapped {
                cap,
                col_size,
                data: std::collections::VecDeque::new(),
            }
        }

        pub fn push_row(&mut self, row: Vec<T>) -> Result<(), &'static str> {
            if row.len() != self.col_size && self.col_size != 0 {
                return Err("row length does not match column size");
            }
            if self.cap > 0 && self.data.len() == self.cap {
                self.data.pop_front();
            }
            self.data.push_back(row);
            Ok(())
        }

        pub fn len(&self) -> usize {
            self.data.len()
        }

        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        pub fn iter(&self) -> impl Iterator<Item = &Vec<T>> {
            self.data.iter()
        }
    }

    impl<T> Index<usize> for VecvecCapped<T> {
        type Output = Vec<T>;
        fn index(&self, idx: usize) -> &Self::Output {
            &self.data[idx]
        }
    }

    pub type VecvecCappedF32 = VecvecCapped<f32>;

    /// A single timestep of behavioral features derived from a ProcessRecord.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Timestep {
        pub gid: u64,
        pub exe: String,
        pub features: Vec<f32>,
    }

    impl Timestep {
        pub fn to_vec_f32(&self) -> Vec<f32> {
            self.features.clone()
        }
    }

    impl From<&ProcessRecord> for Timestep {
        fn from(rec: &ProcessRecord) -> Self {
            Timestep {
                gid: rec.gid,
                exe: rec.exepath.to_string_lossy().to_string(),
                features: vec![],
            }
        }
    }
}
