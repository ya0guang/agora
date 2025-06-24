use iced_asm::Register;

use crate::{Expr, GenericExpr, Location, LocationSub, Sub};

pub trait RegisterTrait {
    fn register(&self) -> Register;
}

impl RegisterTrait for Register {
    fn register(&self) -> Register {
        *self
    }
}

impl RegisterTrait for Sub<Register> {
    fn register(&self) -> Register {
        self.loc
    }
}

pub trait LHSValue {}

impl LHSValue for Location {}
impl LHSValue for LocationSub {}

pub trait RHSValue {}

impl RHSValue for Expr {}
impl RHSValue for GenericExpr<LocationSub> {}

pub trait SSAForm {
    fn get_subscript(&self) -> usize;
}
