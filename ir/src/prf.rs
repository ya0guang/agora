use crate::smt::*;
use crate::*;
use iced_asm::Register;

/// Serialize to human readable proof
pub trait OutputPrf {
    fn output_prf(&self) -> String;
}

impl OutputPrf for Proof {
    fn output_prf(&self) -> String {
        match self {
            Proof::Asgn(assignment) => assignment.output_prf(),
            Proof::Rel(relationship) => relationship.output_prf(),
            Proof::Hint(policy, rel) => match rel {
                Some(r) => format!("HINT {} {}", policy, r.output_prf()),
                None => format!("HINT {}", policy),
            },
            Proof::Anno(annotation) => annotation.output_prf(),
        }
    }
}

impl OutputPrf for Assignment {
    fn output_prf(&self) -> String {
        format!("{} := {}", self.lhs.output_prf(), self.rhs.output_prf())
    }
}

impl OutputPrf for Relationship {
    fn output_prf(&self) -> String {
        format!(
            "{} {} {}",
            self.relationship.output_prf(),
            self.lhs.output_prf(),
            self.rhs.output_prf()
        )
    }
}

impl OutputPrf for Annotation {
    fn output_prf(&self) -> String {
        match self {
            Annotation::Inv(inv) => format!("INV {}", inv.output_prf()),
            Annotation::Branch(branch) => {
                format!("BRANCH {} {}", branch.label, branch.condition.output_prf())
            }
        }
    }
}

impl OutputPrf for AnnotationInvariant {
    fn output_prf(&self) -> String {
        match self {
            AnnotationInvariant::ExprInv(expr) => format!("{}", expr.output_prf()),
            AnnotationInvariant::RelInv(rel) => format!("{}", rel.output_prf()),
        }
    }
}

impl OutputPrf for UnaryOp {
    fn output_prf(&self) -> String {
        match self {
            UnaryOp::Boolean(bop) => bop.output_prf(),
            UnaryOp::BV(bvop) => bvop.output_prf(),
        }
    }
}

impl OutputPrf for BinaryOp {
    fn output_prf(&self) -> String {
        match self {
            BinaryOp::Boolean(bop) => bop.output_prf(),
            BinaryOp::BV(bvop) => bvop.output_prf(),
        }
    }
}

impl OutputPrf for Expr {
    fn output_prf(&self) -> String {
        match self {
            Expr::Var(var) => var.output_prf(),
            Expr::Imm(imm) => imm.output_prf(),
            Expr::Unary(unary_op, expr) => {
                format!("{} {}", unary_op.output_prf(), expr.output_prf())
            }
            Expr::Binary(binary_op, left, right) => {
                format!(
                    "{} {} {}",
                    binary_op.output_prf(),
                    left.output_prf(),
                    right.output_prf()
                )
            }
            // Maybe cut this print?
            Expr::Ite(rel, ethen, eelse) => {
                format!(
                    "ITE {} {} {}",
                    rel.output_prf(),
                    ethen.output_prf(),
                    eelse.output_prf()
                )
            }
            Expr::Const(c) => c.name.clone(),
            Expr::Any(_) | Expr::Alias(_) => panic!("Any/Alias should not be printed!"),
        }
    }
}

impl OutputPrf for BVBinaryOp {
    fn output_prf(&self) -> String {
        match self {
            BVBinaryOp::Arith(arith) => arith.output_prf(),
            BVBinaryOp::Relation(relation) => relation.output_prf(),
        }
    }
}

impl OutputPrf for Location {
    fn output_prf(&self) -> String {
        match &self {
            Location::Flag(f) => f.output_prf(),
            Location::Register(r) => r.output_prf(),
            Location::Memory(m) => m.output_prf(),
            Location::MAS(mas) => mas.output_prf(),
            Location::Stack(_) => panic!("Stack should not be printed!"),
        }
    }
}

impl OutputPrf for MemCell {
    fn output_prf(&self) -> String {
        let mut result = String::new();
        let mut need_plus_sym = false;
        // TODO: use closure to reduce LoC
        if self.segment_reg != Register::None {
            result.push_str(&format!(
                "{}",
                LocationBuilder::new()
                    .register(self.segment_reg)
                    .build()
                    .output_prf()
            ));
            need_plus_sym = true;
        }
        if self.base_reg != Register::None {
            if need_plus_sym {
                result.push_str(" + ");
            };
            result.push_str(&format!(
                "{}",
                LocationBuilder::new()
                    .register(self.base_reg)
                    .build()
                    .output_prf()
            ));
            need_plus_sym = true;
        }
        if self.index_reg != Register::None {
            if need_plus_sym {
                result.push_str(" + ");
            };
            result.push_str(&format!(
                "({} * {})",
                LocationBuilder::new()
                    .register(self.index_reg)
                    .build()
                    .output_prf(),
                self.scale.unwrap()
            ));
            need_plus_sym = true;
        }
        if self.displacement != 0 {
            if need_plus_sym {
                result.push_str(" + ");
            };
            result.push_str(&format!("{}", Imm::from(self.displacement).output_prf()));
        }
        format!("{}[{}]", self.size.output_prf(), result)
    }
}

impl OutputPrf for Imm {
    fn output_prf(&self) -> String {
        let mut string = self.stringify_expr().unwrap();
        match self.size.get_sort() {
            Sort::Bool => string,
            Sort::BitVec(_) => {
                string.remove_matches("#x");
                format!("0x{}", string)
            }
        }
    }
}

impl OutputPrf for Register {
    fn output_prf(&self) -> String {
        let s = format!("{:?}", self);
        s.to_lowercase()
    }
}
