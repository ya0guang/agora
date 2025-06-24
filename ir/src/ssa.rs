use crate::*;
use iced_asm::Register;
use std::collections::HashSet;

pub type Subscript = usize;
// We're ruling out memory locations
pub type SSALocation = GenericLocation<SubRegister>;

// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
// pub struct SSARegister(pub Register, pub Subscript);

// SSA form location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sub<T> {
    pub loc: T,
    pub sub: Subscript,
}

// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
// pub struct MaybeSub<T> {
//     pub location: T,
//     pub sub: Option<Subscript>,
// }

impl<T> Sub<T> {
    pub fn from(location: T, sub: Subscript) -> Self {
        Self { loc: location, sub }
    }

    pub fn get_loc(&self) -> &T {
        &self.loc
    }
}

impl<T> SSAForm for Sub<T> {
    fn get_subscript(&self) -> usize {
        self.sub
    }
}

pub type SubRegister = Sub<Register>;
pub type LocationSub = Sub<GenericLocation<SubRegister>>;

impl Into<LocationSub> for SubRegister {
    fn into(self) -> LocationSub {
        LocationSub::from(GenericLocation::Register(self.loc), self.sub)
    }
}

impl<T: LocationType> LocationType for Sub<T> {
    fn is_memory(&self) -> bool {
        self.loc.is_memory()
    }

    fn is_flag(&self) -> bool {
        self.loc.is_flag()
    }

    fn is_register(&self) -> bool {
        self.loc.is_register()
    }
}

// static single assignment
pub type SSAsgn = GenericAssignment<LocationSub, LocationSub>;
// SSA from expression
pub type SSRel = GenericRelationship<LocationSub>;
// pub type SSExpr = GenericExpr<LocationSub>;
pub type SSExpr = GenericExpr<LocationSub>;

pub type SSAAssignments = Vec<SSAsgn>;
pub type SSARelationships = Vec<SSRel>;

impl SSExpr {
    pub fn stack_uses(&self) -> HashSet<LocationSub> {
        let mut result = HashSet::new();
        match self {
            SSExpr::Var(v) => {
                if v.is_memory() {
                    let memcell = v.loc.try_take_memcell().unwrap();
                    if memcell.is_rsp_ralted() {
                        result.insert(v.clone());
                    }
                }
            }
            SSExpr::Unary(_, e) => result.extend(e.stack_uses()),
            SSExpr::Binary(_, e1, e2) => {
                result.extend(e1.stack_uses());
                result.extend(e2.stack_uses());
            }
            SSExpr::Ite(econd, ethen, eelse) => {
                result.extend(econd.stack_uses());
                result.extend(ethen.stack_uses());
                result.extend(eelse.stack_uses());
            }
            _ => {}
        }
        return result;
    }
}

impl Into<MemCell> for GenericMemCell<SubRegister> {
    fn into(self) -> MemCell {
        MemCell {
            base_reg: *self.base_reg.get_loc(),
            index_reg: *self.index_reg.get_loc(),
            displacement: self.displacement,
            index_scale_negtive: self.index_scale_negtive,
            scale: self.scale,
            size: self.size,
        }
    }
}

impl Into<Location> for LocationSub {
    fn into(self) -> Location {
        match self.loc {
            GenericLocation::Flag(f) => Location::Flag(f),
            GenericLocation::MAS(mas) => Location::MAS(mas),
            GenericLocation::Register(r) => Location::Register(r),
            GenericLocation::Memory(m) => {
                let mcb = MemCellBuilder::new()
                    .base_reg(*m.base_reg.get_loc())
                    .index_reg(*m.index_reg.get_loc())
                    .displacement(m.displacement)
                    .scale(m.scale.clone())
                    .size(m.size);
                Location::Memory(mcb.build())
            }
            GenericLocation::Stack(s) => Location::Stack(s),
        }
    }
}
