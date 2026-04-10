use zeroize::Zeroize;

#[derive(Clone)]
pub struct TBox {
    pub round: usize,
    pub byte_idx: usize,
    pub table: [u8; 256],
}

#[derive(Clone)]
pub struct TypeI {
    pub round: usize,
    pub tables: Vec<[[u8; 256]; 4]>,
}

#[derive(Clone)]
pub struct TypeII {
    pub round: usize,
    pub tables: Vec<[[u8; 256]; 4]>,
}

#[derive(Clone)]
pub struct WhiteBoxTables {
    pub t_boxes: Vec<TBox>,
    pub type_i: Vec<TypeI>,
    pub type_ii: Vec<TypeII>,
    pub randomization: Vec<[u8; 16]>,
}

impl WhiteBoxTables {
    pub fn new() -> Self {
        Self {
            t_boxes: Vec::new(),
            type_i: Vec::new(),
            type_ii: Vec::new(),
            randomization: Vec::new(),
        }
    }

    pub fn randomize(&mut self) {
        for _ in 0..16 {
            let bijection: [u8; 16] = rand::random();
            self.randomization.push(bijection);
        }

        for (i, t_box) in self.t_boxes.iter_mut().enumerate() {
            let rand_idx = i % self.randomization.len();
            let rand_val = &self.randomization[rand_idx];

            for (j, entry) in t_box.table.iter_mut().enumerate() {
                *entry ^= rand_val[j % 16];
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.t_boxes.len() as u32).to_le_bytes());

        for t_box in &self.t_boxes {
            bytes.push(t_box.round as u8);
            bytes.push(t_box.byte_idx as u8);
            bytes.extend_from_slice(&t_box.table);
        }

        bytes.extend_from_slice(&(self.type_i.len() as u32).to_le_bytes());

        for type_i in &self.type_i {
            bytes.push(type_i.round as u8);
            for column_table in &type_i.tables {
                for row_table in column_table {
                    bytes.extend_from_slice(row_table);
                }
            }
        }

        bytes.extend_from_slice(&(self.type_ii.len() as u32).to_le_bytes());

        bytes
    }

    pub fn estimate_size(&self) -> usize {
        let t_box_size = self.t_boxes.len() * (2 + 256);
        let type_i_size = self.type_i.len() * (1 + 4 * 4 * 256);
        let type_ii_size = self.type_ii.len() * (1 + 4 * 4 * 256);

        t_box_size + type_i_size + type_ii_size + 1000
    }

    pub fn zeroize(&mut self) {
        for t_box in &mut self.t_boxes {
            t_box.table.zeroize();
        }
        self.randomization.zeroize();
    }
}

impl Default for WhiteBoxTables {
    fn default() -> Self {
        Self::new()
    }
}
