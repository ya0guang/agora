use anyhow::{anyhow, Result};
use ir::{ast::*, boolean, bv, expr, rel, utils::*, Location, Sort, SortInfer, Sorted};
use log::debug;
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use std::collections::HashMap;

#[derive(Parser)]
#[grammar = "proof.pest"]
pub struct ProofParser;

/// Parse the proof file into a `Proof` struct
/// Type checking is performed in each sub-proof converters
pub fn parse(source: &str) -> Result<HashMap<u64, Vec<Proof>>> {
    let proof = ProofParser::parse(Rule::file, source).expect("Parsing proof file failed");
    let mut whole_proof: HashMap<u64, Vec<Proof>> = HashMap::new();
    for pair in proof.flatten() {
        match pair.as_rule() {
            Rule::line => {
                let (line, prf) = parse_line(pair)?;
                // check_type(line, &prf)?;
                if whole_proof.contains_key(&line) {
                    whole_proof.get_mut(&line).unwrap().push(prf);
                } else {
                    whole_proof.insert(line, Vec::new());
                    whole_proof.get_mut(&line).unwrap().push(prf);
                }
            }
            _ => {}
        }
    }
    Ok(whole_proof)
}

pub fn parse_proof_str(source: &str) -> Result<Proof> {
    let mut proof = ProofParser::parse(Rule::proof, source).expect("Parsing proof line failed");
    let p = proof.next().unwrap();
    parse_proof(p)
}

// pub fn check_type(line: u64, prf: &Proof) -> Result<()> {
//     trace!("Checking type of proof line: {:x}, proof {:?}", line, prf);
//     match prf {
//         Proof::Asgn(a) => a.check_sort()?,
//         Proof::Rel(r) | Proof::Hint(_, r) => {
//             debug!(
//                 "Checking sort of relationship: {:?}, {:?}",
//                 r.left_hand_side.infer_sort()?,
//                 r.right_hand_side.infer_sort()?
//             );
//             r.check_sort()?;
//         }
//         Proof::Anno(_) => {
//             unimplemented!()
//         }
//     }
//     Ok(())
// }

fn parse_line(l: Pair<Rule>) -> Result<(u64, Proof)> {
    let mut pairs = l.into_inner();
    let index = pairs.next().unwrap();
    let index = parse_hex(index)?;
    debug!("Parsing proof line: 0x{:x}", index);
    let proof = pairs.next().unwrap();
    let proof = parse_proof(proof)?;
    Ok((index, proof))
}

pub fn parse_proof(p: Pair<Rule>) -> Result<Proof> {
    debug!("Parsing proof: {:?}", p);
    let result = match p.as_rule() {
        Rule::proof => {
            let p = p.into_inner().next().unwrap();
            match p.as_rule() {
                Rule::annotation => Proof::Anno(parse_annotation(p)?),
                Rule::assignment => Proof::Asgn(parse_assignment(p)?),
                Rule::relationship => Proof::Rel(parse_relationship(p)?),
                Rule::hint => {
                    let mut inner = p.into_inner();
                    let hint_name = String::from(inner.next().unwrap().as_str());
                    match inner.next() {
                        Some(rel) => Proof::Hint(hint_name, Some(parse_relationship(rel)?)),
                        None => Proof::Hint(hint_name, None),
                    }
                }
                _ => panic!("Proof mismatched"),
            }
        }
        _ => panic!("Proof mismatched"),
    };
    Ok(result)
}

fn parse_annotation(proof: Pair<Rule>) -> Result<Annotation> {
    // debug!("DEBUG: parsing annotation: {:?}", proof);
    let mut pairs = proof.into_inner();
    let anno = pairs.next().unwrap();
    match anno.as_rule() {
        Rule::invariant => {
            let mut inner = anno.into_inner();
            let inv = inner.next().unwrap();
            match inv.as_rule() {
                Rule::expr => Ok(Annotation::Inv(AnnotationInvariant::ExprInv(
                    parse_expr(inv).unwrap().0,
                ))),
                Rule::relationship => Ok(Annotation::Inv(AnnotationInvariant::RelInv(
                    parse_relationship(inv).unwrap(),
                ))),
                _ => {
                    return Err(anyhow::anyhow!("Invalid invariant annotation",));
                }
            }
        }
        Rule::branch_cond => {
            // println!("DEBUG: parsing branch condition: {:?}", anno);
            let mut inner = anno.into_inner();
            let label = inner.next().unwrap().as_str().to_owned();
            let rel = parse_relationship(inner.next().unwrap())?;
            Ok(Annotation::Branch(AnnotationBranch {
                label,
                condition: rel,
            }))
        }
        _ => Err(anyhow::anyhow!("Invalid annotation")),
    }
}

fn parse_assignment(proof: Pair<Rule>) -> Result<Assignment> {
    debug!("Parsing assignment: {:?}", proof);
    let mut assignment = proof.into_inner();
    let loc = assignment.next().unwrap();
    let (lhs_var, lhs_sort) = match loc.as_rule() {
        Rule::boolean_location => (parse_boolean_location(loc)?, Sort::Bool),
        Rule::bv_location => parse_bv_location(loc)?,
        _ => return Err(anyhow::anyhow!("Invalid assignment LHS")),
    };
    // We only allow FULL REGISTER, FLAG, or memory to appear on lhs
    assert_eq!(
        lhs_var,
        unalias_location(lhs_var)?,
        "LHS location must be fully unaliased!"
    );
    let (expr, rhs_sort) = parse_expr(assignment.next().unwrap())?;
    // always cast to lhs sort
    return Ok(Assignment {
        lhs: lhs_var,
        rhs: tease_expr(rhs_sort.cast(lhs_sort)?(expr), None)?,
    });
}

fn parse_relationship(proof: Pair<Rule>) -> Result<Relationship> {
    let mut relationship = proof.into_inner().next().unwrap().into_inner();
    let binary_rel = relationship.next().unwrap().as_str();
    let (lhs, rhs, sort) = deal_two_exprs(&mut relationship)?;
    let binary_rel = match sort {
        Sort::BitVec(_) => bv!(binary_rel),
        Sort::Bool => boolean!(binary_rel),
    };
    return Ok(rel! {tease_expr(lhs, None)?, binary_rel, tease_expr(rhs, None)?});
}

fn parse_expr(expr: Pair<Rule>) -> Result<(Expr, Sort)> {
    let (expr, sort) = do_parse_expr(expr)?;
    Ok((tease_expr(expr, None)?, sort))
}

fn do_parse_expr(expr: Pair<Rule>) -> Result<(Expr, Sort)> {
    // let mut expr = expr.into_inner().next().unwrap();
    let expect_sort = match expr.as_rule() {
        Rule::boolean_expr => Sort::Bool,
        Rule::bv_expr => Sort::BitVec(128), // always accepting BV64 as the top sort
        _ => panic!("Expr {:?} mismatched", expr),
    };
    let inner_expr = expr.into_inner().next().unwrap();
    let (actual_expr, actual_sort) = match inner_expr.as_rule() {
        Rule::boolean_location => (Expr::Var(parse_boolean_location(inner_expr)?), Sort::Bool),
        Rule::bv_location => {
            let (loc, sort) = parse_bv_location(inner_expr)?;
            if let Location::Register(r) = loc {
                // Transcript the partial registers to full registers (avoid its uses)
                if r == r.full_register() || r.is_xmm() {
                    (Expr::Var(loc), sort)
                } else {
                    if r.size() == 4 || r.size() == 2 {
                        (
                            Sort::BitVec(64).cast(sort)?(Expr::Var(Location::Register(
                                r.full_register(),
                            ))),
                            sort,
                        )
                    } else {
                        return Err(anyhow!("Invalid register size: {}", r.size()));
                    }
                }
            } else {
                (Expr::Var(loc), sort)
            }
        }
        Rule::hex_num => {
            let (imm, sort) = parse_imm(inner_expr)?;
            (Expr::Imm(imm), sort)
        }
        Rule::boolean => (Expr::Imm(parse_boolean(inner_expr)?), Sort::Bool),
        Rule::boolean_unary_expr => {
            let mut unary_expr = inner_expr.into_inner();
            let op = UnaryOp::Boolean(BooleanUnaryOp::try_from(
                unary_expr.next().unwrap().as_str(),
            )?);
            let (expr1, sort) = parse_expr(unary_expr.next().unwrap())?;
            (Expr::Unary(op, Box::new(expr1)), sort)
        }
        Rule::bv_unary_expr => {
            let mut unary_expr = inner_expr.into_inner();
            debug!("Parsing bv unary expression: {:?}", unary_expr);
            let op = UnaryOp::BV(BVUnaryOp::try_from(unary_expr.next().unwrap().as_str())?);
            let (expr1, _) = parse_expr(unary_expr.next().unwrap())?;
            let expr = Expr::Unary(op, Box::new(expr1));
            let sort = expr.infer_sort()?;
            // return the sort of expr, since unary operations(extract/extend) may change sort
            (expr, sort)
        }
        Rule::boolean_binary_expr => {
            let mut binary_expr = inner_expr.into_inner();
            let op = boolean!(binary_expr.next().unwrap().as_str());
            let (expr1, expr2, sort) = deal_two_exprs(&mut binary_expr)?;
            Sort::compatible(sort, Sort::Bool)?;
            (expr!(expr1, op, expr2), Sort::Bool)
        }

        Rule::bv_binary_expr => {
            let mut binary_expr = inner_expr.into_inner();
            let op = bv!(binary_expr.next().unwrap().as_str());
            let (expr1, expr2, sort) = deal_two_exprs(&mut binary_expr)?;
            (expr!(expr1, op, expr2), sort)
        }
        Rule::bv_relationship => {
            let mut binary_expr = inner_expr.into_inner();
            let op = BinaryOp::BV(BVBinaryOp::Relation(BVBinaryRelation::try_from(
                binary_expr.next().unwrap().as_str(),
            )?));
            let (expr1, expr2, _) = deal_two_exprs(&mut binary_expr)?;
            (expr!(expr1, op, expr2), Sort::Bool)
        }
        Rule::ite_expr => {
            let mut ite_expr = inner_expr.into_inner();
            let (cond, sort_cond) = parse_expr(ite_expr.next().unwrap())?;
            let (ethen, eelse, sort) = deal_two_exprs(&mut ite_expr)?;
            Sort::compatible(sort_cond, Sort::Bool)?;
            (
                Expr::Ite(Box::new(cond), Box::new(ethen), Box::new(eelse)),
                sort,
            )
        }
        Rule::bv_const_expr => {
            debug!("Parsing expr: {:?}", inner_expr);
            let expr = inner_expr.as_str();
            (
                Expr::Const(Const::new(Sort::BitVec(64), expr.to_string())),
                Sort::BitVec(64),
            )
        }
        // Don't allow any in proof!
        // Rule::any => Expr::Any,
        _ => return Err(anyhow::anyhow!("Expr mismatched, {:?}", inner_expr)),
    };
    assert!((expect_sort >= actual_sort && actual_sort > Sort::Bool) || expect_sort == actual_sort);
    Ok((actual_expr, actual_sort))
}

fn deal_two_exprs(exprs: &mut Pairs<Rule>) -> Result<(Expr, Expr, Sort)> {
    debug!("Parsing two expressions: {:?}", exprs);
    let (expr1, sort1) = parse_expr(exprs.next().unwrap())?;
    let (expr2, sort2) = parse_expr(exprs.next().unwrap())?;
    let target_sort = Sort::compatible(sort1, sort2)?;
    Ok((
        sort1.cast(target_sort)?(expr1),
        sort2.cast(target_sort)?(expr2),
        target_sort,
    ))
}

fn parse_boolean_location(loc: Pair<Rule>) -> Result<Location> {
    let vb = LocationBuilder::new();
    let inner = loc.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::flags => Ok(vb.flag(Flags::try_from(inner.as_str())?).build()),
        Rule::microarch_states => Ok(vb
            .mas(MicroArchitecturalState::try_from(inner.as_str())?)
            .build()),
        _ => Err(anyhow::anyhow!("Boolean location mismatched")),
    }
}

fn parse_bv_location(var: Pair<Rule>) -> Result<(Location, Sort)> {
    debug!("parsing bv location: {:?}", var);
    let var_builder = LocationBuilder::new();
    let mut inner = var.into_inner();
    let var = inner.next().unwrap();
    let var = match var.as_rule() {
        Rule::register => {
            let reg_pair = var.into_inner().next().unwrap();
            var_builder
                .register(get_register(reg_pair.as_str())?)
                .build()
        }
        Rule::memory => var_builder.memcell(parse_memcell(var)?).build(),
        _ => return Err(anyhow::anyhow!("Location mismatched")),
    };

    Ok((var, var.infer_sort()?))
}

fn parse_boolean(imm: Pair<Rule>) -> Result<Imm> {
    debug!("Parsing bool: {:?}", imm);
    let bool_string = imm.as_str().to_owned();
    if bool_string == "true" {
        Ok(Imm::new(1, ValSize::Size1))
    } else if bool_string == "false" {
        Ok(Imm::new(0, ValSize::Size1))
    } else {
        Err(anyhow::anyhow!("Boolean mismatch"))
    }
}

fn parse_imm(imm: Pair<Rule>) -> Result<(Imm, Sort)> {
    let mut hex_string = imm.as_str().to_owned();
    hex_string.remove_matches("0x");
    let value = match u64::from_str_radix(&hex_string, 16) {
        Ok(i) => Ok(i),
        Err(_) => Err(anyhow::anyhow!("Hex number reading error in parse_imm")),
    }?;
    let imm = if hex_string.len() <= 32 && hex_string.len() > 16 {
        Imm::from(value as u128)
    } else if hex_string.len() <= 16 && hex_string.len() > 8 {
        Imm::from(value as u64)
    } else if hex_string.len() <= 8 && hex_string.len() > 4 {
        //  Conduct convert twice to maintain sign information
        Imm::from(value as i32)
    } else if hex_string.len() <= 4 && hex_string.len() > 2 {
        Imm::from(value as i16)
    } else if hex_string.len() <= 2 {
        Imm::from(value as i8)
    } else {
        return Err(anyhow::anyhow!("Hex number length mismatch"));
    };
    let sort = imm.get_sort();
    Ok((imm, sort))
}

fn parse_memcell(mem: Pair<Rule>) -> Result<MemCell> {
    // println!("DEBUG: parsing memcell: {:?}", mem);
    let mut mcb = MemCellBuilder::new();
    for p in mem.into_inner() {
        match p.as_rule() {
            Rule::size_prefix => {
                let size = ValSize::try_from(p.as_str())?;
                mcb = mcb.size(size);
            }
            Rule::register64 => {
                let reg = get_register(p.as_str())?;
                mcb = mcb.base_reg(reg);
            }
            Rule::hex_num => {
                let disp = parse_hex(p)?;
                mcb = mcb.displacement(disp as _);
            }
            Rule::indscale => {
                let mut indscale = p.into_inner();
                let ind_pair = indscale.next().unwrap();
                let ind_reg = get_register(ind_pair.as_str())?;
                mcb = mcb.index_reg(ind_reg);
                let scale_pair = indscale.next().unwrap();
                let scale: u8 = scale_pair.as_str().parse()?;
                mcb = mcb.scale(Some(scale));
            }
            Rule::memory_pm => {
                if p.as_str() == "-" {
                    mcb = mcb.next_negtivity(true);
                }
            }
            _ => return Err(anyhow::anyhow!("Memcell mismatched")),
        }
    }
    Ok(mcb.build())
}

fn parse_hex(hex: Pair<Rule>) -> Result<u64> {
    let mut hex_string = hex.as_str().to_owned();
    hex_string.remove_matches("0x");
    match u64::from_str_radix(&hex_string, 16) {
        Ok(i) => Ok(i),
        Err(_) => Err(anyhow::anyhow!("Hex number reading error in parse_hex")),
    }
}

#[cfg(test)]
mod parser_tests {
    use crate::{
        parse::{ProofParser, Rule},
        parse_proof_str,
    };
    use pest::Parser;
    use std::fs;

    #[test]
    fn test_debug() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
                .try_init();
        let proof = "d[rdi] := (extract 32 0) bvand rsi 0x00000000ffffffff";
        let res = ProofParser::parse(Rule::assignment, proof).unwrap();
        println!("{:?}", res);
        let prf = parse_proof_str(proof);
        println!("{:?}", prf);
    }

    #[test]
    fn test_assigments() {
        let asgn_reg1 = "r15 := bvadd r14 r13";
        let asgn_reg2 = "rsp := bvadd bvadd r14 0x0000000000000012 bvsub rbp r12";
        let asgn_reg3 = "rsp := bvadd bvneg r14 bvsub rbp r12";
        let asgn_reg4 = "rcx := bvudiv bvand rax 0x000000000000FFFF bvlshr rbx 0x0000000000000004";
        let asgn_reg5 = "rdx := bvurem bvand rax 0x000000000000FFFF bvlshr rbx bvxor rbp rsp";

        let asgn_flag1 = "ZF := bvugt r14 0x100";
        let asgn_flag2 = "ZF := bvuge rax bvadd rsp 0x100";
        let asgn_flag3 = "CF := distinct rax bvmul rsp 0x10";

        let asgn_mem1 = "q[rax + 0x100] := bvadd r14 0x100";

        let asgn_fail1 = "+ r14 r15 := bvadd r14 r13";
        // not covered completedly by the parsed span! should be considered as fail.
        let _asgn_fail2 = "r15 := r14 + r13";

        assert!(ProofParser::parse(Rule::assignment, asgn_reg1).is_ok());
        assert!(ProofParser::parse(Rule::assignment, asgn_reg2).is_ok());
        assert!(ProofParser::parse(Rule::assignment, asgn_reg3).is_ok());
        assert!(ProofParser::parse(Rule::assignment, asgn_reg4).is_ok());
        assert!(ProofParser::parse(Rule::assignment, asgn_reg5).is_ok());
        assert!(ProofParser::parse(Rule::assignment, asgn_flag1).is_ok());
        assert!(ProofParser::parse(Rule::assignment, asgn_flag2).is_ok());
        assert!(ProofParser::parse(Rule::assignment, asgn_flag3).is_ok());
        let _result = ProofParser::parse(Rule::assignment, asgn_mem1);
        // println!("{:?}", result);
        // assert!(ProofParser::parse(Rule::assignment, asgn_mem1).is_ok());

        assert!(ProofParser::parse(Rule::assignment, asgn_fail1).is_err());
    }

    #[test]
    fn test_relationships() {
        let rel_reg1 = "= rax rsp";
        let rel_reg2 = "distinct r15 bvadd r14 0x80";
        let rel_reg3 = "= rax bvmul r14d 0x00";
        let rel_reg4 = "bvugt bvadd rax bvadd rsp 0x04 bvmul rsp bvsub rbp r12";

        let rel_flag = "distinct ZF CF";

        let rel_const = "= rdi GlobalBase";

        assert!(ProofParser::parse(Rule::relationship, rel_reg1).is_ok());
        assert!(ProofParser::parse(Rule::relationship, rel_reg2).is_ok());
        assert!(ProofParser::parse(Rule::relationship, rel_reg3).is_ok());
        assert!(ProofParser::parse(Rule::relationship, rel_reg4).is_ok());
        assert!(ProofParser::parse(Rule::relationship, rel_flag).is_ok());
        assert!(ProofParser::parse(Rule::relationship, rel_const).is_ok());

        // debug
        // println!("{:?}", ProofParser::parse(Rule::relationship, rel_reg4));
    }

    #[test]
    fn test_annotations() {
        let anno_inv1 = "INV = rsp 0x8000";
        let anno_inv2 = "INV bvuge rsp bvadd rbp 0x0FF";
        let anno_bc1 = "BRANCH .labelX distinct rsp rbp";
        let anno_bc2 = "BRANCH .BB03 = rsp rbp";

        assert!(ProofParser::parse(Rule::annotation, anno_inv1).is_ok());
        assert!(ProofParser::parse(Rule::annotation, anno_inv2).is_ok());
        assert!(ProofParser::parse(Rule::annotation, anno_bc1).is_ok());
        assert!(ProofParser::parse(Rule::annotation, anno_bc2).is_ok());

        // debug
        println!("{:?}", ProofParser::parse(Rule::annotation, anno_bc2));
    }

    #[test]
    fn test_file() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
                .try_init();
        let proof_file = fs::read_to_string("sample.prf").expect("Could not read proof file");
        let proof = crate::parse(&proof_file).unwrap();
        // let proof = proof_file
        //     .expect("unsuccessful parse") // unwrap the parse result
        //     .next()
        //     .unwrap();

        println!("file parsed: {:?}", proof);
    }
}
