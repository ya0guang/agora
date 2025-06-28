use ir::smt::{StringifyExpr, StringifySort, StringifySym};
use rsmt2::print::{Sort2Smt, Sym2Smt};
use rsmt2::{SmtConf, Solver};
// use log::{debug, error, info, trace, warn};
use crate::dis::ControlFlowInfo;
use crate::policy::{Constraints, HintAssertWithInfo, Policy, Verifier};
use crate::ssa::*;
use crate::validate::AssertWithInfo;
use anyhow::{anyhow, Ok, Result};
use core::hash::Hash;
use iced_asm::Register;
use ir::*;
use lazy_static::lazy_static;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::ops::Bound::Included;

// This wrapper make solverless mode more readable
macro_rules! solverless {
    ($pred: expr, $exp: expr) => {
        if !$pred {
            $exp
        }
    };
}

struct SolverContext<'a>
where
// L: LHSValue,
// GenericExpr<T>: RHSValue,
{
    pub solver: Solver<()>,
    declared_locs: HashSet<String>,
    declared_branches: HashSet<(u64, u64)>,
    output_file: File,
    asserted_aliases: HashSet<(LocationSub, Alias)>,
    verifier: &'a Verifier,
}

lazy_static! {
    pub static ref SSEXPR_TRUE: GenericExpr<Sub<GenericLocation<Sub<Register>>>> =
        Const::new(Sort::Bool, String::from("true")).into();
    pub static ref SSEXPR_FALSE: GenericExpr<Sub<GenericLocation<Sub<Register>>>> =
        Const::new(Sort::Bool, "false".to_string()).into();
}

pub fn unify_ssexprs(asserts: &[SSExpr], unifier: BinaryOp) -> SSExpr {
    // println!("unify_ssexprs invoked");
    match asserts.len() {
        0 => SSEXPR_TRUE.clone(),
        1 => asserts[0].clone(),
        _ => expr!(
            asserts[0].clone(),
            unifier,
            unify_ssexprs(&asserts[1..], unifier)
        ),
    }
}

fn variables_in_expr<T: StringifySym + Sorted>(
    expr: &GenericExpr<T>,
) -> Result<HashMap<String, Sort>> {
    let mut result = HashMap::new();
    match expr {
        GenericExpr::Var(v) => {
            result.insert(v.stringify_sym()?, v.get_sort());
        }
        GenericExpr::Alias(v) => {
            result.insert(v.stringify_sym()?, v.get_sort());
        }
        GenericExpr::Const(v) => {
            if v.name != "true" && v.name != "false" {
                result.insert(v.stringify_sym()?, v.sort);
            }
        }
        GenericExpr::Imm(_) | GenericExpr::Any(_) => {}
        GenericExpr::Ite(eif, ethen, eelse) => {
            result.extend(variables_in_expr(eif)?);
            result.extend(variables_in_expr(ethen)?);
            result.extend(variables_in_expr(eelse)?);
        }
        GenericExpr::Binary(_, e1, e2) => {
            result.extend(variables_in_expr(e1)?);
            result.extend(variables_in_expr(e2)?);
        }
        GenericExpr::Unary(_, e) => {
            result.extend(variables_in_expr(e)?);
        }
    }
    Ok(result)
}

fn variables_in_asgn<L, T>(asgn: &GenericAssignment<L, T>) -> Result<HashMap<String, Sort>>
where
    GenericExpr<T>: RHSValue,
    L: LHSValue + StringifySym + Sorted,
    T: Sorted + StringifySym,
{
    let mut result = variables_in_expr(&asgn.rhs)?;
    result.insert(asgn.lhs.stringify_sym()?, asgn.lhs.get_sort());
    Ok(result)
}

// fn variables_in_rel(rel: &SSRel) -> Result<HashMap<String, Sort>> {
//     let mut result = variables_in_expr(&rel.lhs)?;
//     result.extend(variables_in_expr(&rel.rhs)?);
//     Ok(result)
// }

// fn unify_br_conds_predtosuc(conds: &Vec<SSExpr>) -> SSExpr {
//     match conds.len() {
//         0 => SSEXPR_TRUE.clone(), // happens when there is no successor
//         1 => expr!(conds[0].clone(), boolean!("="), SSEXPR_TRUE.clone()),
//         2 => expr!(conds[0].clone(), boolean!("xor"), conds[1].clone()),
//         _ => panic!("more than 2 successors"),
//     }
// }

macro_rules! debug_write {
    ($output: expr, $($arg:tt)*) => {
        writeln!($output, $($arg)*).unwrap();
    };
}

impl<'a> SolverContext<'a>
// where
//     L: LHSValue,
//     GenericExpr<T>: RHSValue,
//     T: StringifySort + StringifySym + Sort2Smt + Sym2Smt + Hash,
{
    pub fn init_solver_context(mut output_file: File, verifier: &'a Verifier) -> SolverContext<'a> {
        // TODO: declear anys online
        let declared = HashSet::new();
        let solver = SolverContext::init_solver(Some(&mut output_file), verifier.solverless);
        let ctx = SolverContext {
            solver,
            declared_locs: declared,
            declared_branches: HashSet::new(),
            output_file,
            asserted_aliases: HashSet::new(),
            verifier,
        };

        // // Declaring GlobalBase
        // ctx.solver
        //     .declare_const("GlobalBase", "(_ BitVec 64)")
        //     .unwrap();

        // debug_write!(ctx.output_file, "(declare-const GlobalBase (_ BitVec 64))",);
        ctx
    }

    pub fn assert_aliases(&mut self, ssa: &SSAState) -> Result<()> {
        ssa.aliases.iter().try_for_each(|(loc, alias)| {
            // avid repeated assertion
            if self.asserted_aliases.contains(&(*loc, alias.clone())) {
                return Ok(());
            } else {
                self.do_declare(loc)?;
                self.do_declare(alias)?;
                let assertion = expr!(loc.clone().into(), bv!("="), alias.clone().into());
                self.asserted_aliases.insert((*loc, alias.clone()));
                self.assume(&assertion)
            }
        })
    }

    pub fn declare_phis(&mut self, phis: &PhiMap, addr: u64) -> Result<()> {
        for (loc, info) in phis {
            let incoming_locs = info.incoming_locs()(*loc);
            let current_loc = info.current_loc()(*loc);
            // assume that the final value of phi is one of the incoming values
            // if there is only one incoming value, we don't need to assume anything
            if incoming_locs.len() > 1 && self.declared_locs.contains(&current_loc.stringify_sym()?)
            {
                self.debug_info(&format!(
                    "declaring phi for location {:?} at address {:x}",
                    loc, addr
                ))?;
                self.do_declare(&current_loc)?;
                // let mut incoming_addrs = vec![];
                for (incoming_addr, incoming_sub) in info.incoming_map.iter() {
                    let br_cond = self.declare_branch_cond(*incoming_addr, addr)?;
                    // incoming_addrs.push(br_cond.clone());
                    let eq = match loc.get_sort() {
                        Sort::Bool => boolean!("="),
                        Sort::BitVec(_) => bv!("="),
                    };

                    // ITE br_cond (= current = corresponding incoming) true
                    self.do_declare(&Sub::from(loc.clone(), *incoming_sub))?;
                    let br_assumption = SSExpr::Ite(
                        Box::new(Const::new(Sort::Bool, br_cond).into()),
                        Box::new(expr!(
                            current_loc.into(),
                            eq,
                            Sub::from(loc.clone(), *incoming_sub).into()
                        )),
                        Box::new(SSEXPR_TRUE.clone()),
                    );
                    self.assume(&br_assumption)?;
                }
            }
        }
        Ok(())
    }

    fn declare_branch_cond(&mut self, incoming_addr: u64, addr: u64) -> Result<String> {
        let sym = format!("br_cond_{:x}_{:x}", incoming_addr, addr);
        if self.declared_branches.contains(&(incoming_addr, addr)) {
            return Ok(sym);
        } else {
            let sort = Sort::Bool;
            debug_write!(
                self.output_file,
                "(declare-const {} {})",
                sym,
                sort.stringify_sort()?
            );
            solverless!(
                self.verifier.solverless,
                self.solver.declare_const(&sym, &sort).unwrap()
            );
            self.declared_branches.insert((incoming_addr, addr));
            self.declared_locs.insert(sym.clone());
            Ok(sym)
        }
    }

    fn lazy_declare(&mut self, vars: HashMap<String, Sort>) -> Result<()> {
        for (name, sort) in vars {
            if !self.declared_locs.contains(&name) {
                self.do_declare(&Const::new(sort, name))?
            }
        }
        Ok(())
    }

    fn do_declare<U>(&mut self, loc: &U) -> Result<()>
    where
        U: StringifySort + StringifySym + Sym2Smt + Sort2Smt + Hash,
    {
        if self.declared_locs.contains(&loc.stringify_sym()?) {
            return Ok(());
        }
        debug_write!(
            self.output_file,
            "(declare-const {} {})",
            loc.stringify_sym()?,
            loc.stringify_sort()?
        );
        solverless!(
            self.verifier.solverless,
            self.solver.declare_const(&loc, &loc).unwrap()
        );
        self.declared_locs.insert(loc.stringify_sym()?);
        Ok(())
    }

    pub fn assign<L, T>(&mut self, assignments: &Vec<GenericAssignment<L, T>>) -> Result<()>
    where
        GenericExpr<T>: RHSValue + StringifyExpr,
        L: LHSValue + StringifySym + Sorted,
        T: Sorted + StringifySym,
    {
        for a in assignments {
            // if the RHS is any, skip!
            if let GenericExpr::Any(_) = a.rhs {
                continue;
            }
            debug_write!(self.output_file, "(assert {})", a.stringify_expr()?);
            // self.assignments.push(a.clone());
            solverless!(self.verifier.solverless, self.solver.assert(a).unwrap());
        }
        Ok(())
    }

    pub fn debug_info(&mut self, msg: &String) -> Result<()> {
        debug_write!(self.output_file, "; {}", msg);
        Ok(())
    }

    pub fn checked_assume(&mut self, assumptions: &Vec<SSExpr>) -> Result<()> {
        for r in assumptions {
            // #[cfg(not(debug_assertions))]
            {
                // Strong check, can be enabled after flags are supported
                if !self.sandboxed_check(r, true, &vec![])? {
                    return Err(anyhow!(
                        "RELEASE MODE: Assumption {} is not satisfiable",
                        r.stringify_expr()?
                    ));
                }
            }
            // #[cfg(debug_assertions)]
            // {
            //     // very loose check
            //     if !self.sandboxed_check(r, false, &vec![])? {
            //         return Err(anyhow!(
            //             "DEBUG MODE: Assumption {} is not satisfiable",
            //             r.stringify_expr()?
            //         ));
            //     }
            // }
        }
        Ok(())
    }

    pub fn batch_assume(&mut self, assumptions: &Vec<AssertWithInfo>) -> Result<()> {
        for a in assumptions {
            self.assume_with_info(a)?;
        }
        Ok(())
    }

    fn assume_with_info(&mut self, assumption: &AssertWithInfo) -> Result<()> {
        self.debug_info(&assumption.1)?;
        self.assume(&assumption.0)?;
        Ok(())
    }

    fn assume<T: StringifySym + Sorted>(&mut self, assumption: &GenericExpr<T>) -> Result<()> {
        // self.lazy_declare(variables_in_expr(&assumption)?)?;
        debug_write!(
            self.output_file,
            "(assert {})",
            assumption.stringify_expr()?
        );
        solverless!(
            self.verifier.solverless,
            self.solver.assert(assumption).unwrap()
        );
        Ok(())
    }

    pub fn deal_preconditions(
        &mut self,
        preconditions: &Vec<HintAssertWithInfo>,
        branch_conds: &Vec<SSExpr>,
    ) -> Result<bool> {
        if preconditions.is_empty() {
            return Ok(true);
        }
        for (asserts, assumption) in preconditions {
            if asserts.is_empty() {
                continue;
            }

            // self.assertion_constraints(asserts)?;
            // if self.assert_unsat_pop()? == false {
            //     return Ok(false);
            // }

            if !self.sandboxed_batch_check(asserts, branch_conds)? {
                return Err(anyhow!("precondition is not satisfied"));
            }
            self.assume_with_info(assumption)?;
        }
        Ok(true)
    }

    /// check unsatifiability of a vector of Expr in a new stack
    fn sandboxed_batch_check(
        &mut self,
        assertions: &Vec<AssertWithInfo>,
        branch_conds: &Vec<SSExpr>,
    ) -> Result<bool> {
        // Unify and check in the future
        self.debug_info(&"unifying checked assertions".to_string())?;
        let all_asserts: Vec<_> = assertions
            .iter()
            .map(|(assert, info)| {
                self.debug_info(&info).unwrap();
                assert.clone()
            })
            .collect();
        let unified_assertion = unify_ssexprs(&all_asserts, boolean!("and"));
        Ok(self.sandboxed_check(&unified_assertion, true, branch_conds)?)
    }

    /// check the unsatifiability of an Expr in a new stack.
    /// return true if unsatisfiable and unsat is set to true;
    /// return true if satisfiable and unsat is set to false;
    fn sandboxed_check(
        &mut self,
        assertion: &SSExpr,
        unsat: bool,
        branch_conds: &Vec<SSExpr>,
    ) -> Result<bool> {
        if self.verifier.policy == Policy::IFCSafe {
            // unsat = false;
        }

        // sanity check
        if !(assertion.infer_sort()? == Sort::Bool) {
            return Err(anyhow!("assertion is not a boolean expression"));
        }

        debug_write!(self.output_file, "(push 1)");
        solverless!(self.verifier.solverless, self.solver.push(1).unwrap());

        // expect sat guard
        debug_write!(self.output_file, "(check-sat)");
        self.debug_info(&format!("guard: expect sat"))?;
        if !self.verifier.solverless {
            if !self.solver.check_sat().unwrap() {
                return Err(anyhow!("guard: expect sat, but unsat"));
            }
        }

        let assertion = if unsat {
            assertion.negate()
        } else {
            assertion.clone()
        };

        self.debug_info(&format!("assuming branch conditions"))?;
        for bc in branch_conds {
            debug_write!(self.output_file, "(assert {})", bc.stringify_expr()?);
            solverless!(self.verifier.solverless, self.solver.assert(bc).unwrap());
        }

        debug_write!(self.output_file, "(assert {})", assertion.stringify_expr()?);
        solverless!(
            self.verifier.solverless,
            self.solver.assert(assertion).unwrap()
        );

        debug_write!(self.output_file, "(check-sat)");
        self.debug_info(&format!("expect {}", if unsat { "unsat" } else { "sat" }))?;

        debug_write!(self.output_file, "(pop 1)");

        if !self.verifier.solverless {
            let solver_sat = self.solver.check_sat().unwrap();
            self.solver.pop(1).unwrap();
            Ok(solver_sat ^ unsat)
        } else {
            Ok(true)
        }
    }

    fn init_solver(mut logger: Option<&mut dyn Write>, solverless: bool) -> Solver<()> {
        let conf = SmtConf::default_cvc4();
        let mut solver = Solver::new(conf, ()).unwrap();
        let options = vec![(":incremental", "true")];
        for (o, v) in options {
            if let Some(ref mut w) = logger {
                debug_write!(w, "(set-option {} {})", o, v);
            }
            solverless!(solverless, solver.set_option(o, v).unwrap());
        }
        if let Some(ref mut w) = logger {
            debug_write!(w, "(set-logic QF_BV)");
        }

        solverless!(solverless, solver.set_logic(rsmt2::Logic::QF_BV).unwrap());
        solver
    }
}

// TODO: multiple invocations to the solve to conduct different SAT check
pub fn solve_function(
    func_constraints: &BTreeMap<u64, Constraints>,
    ssa_sem: &FuncSSA,
    func_name: &String,
    cfi: &ControlFlowInfo,
    verifier: &Verifier,
) -> Result<()> {
    let smt_log_file = File::create(format!("{}.smt2", func_name.replace("/", "_"))).unwrap();
    let mut solver_ctx = SolverContext::init_solver_context(smt_log_file, verifier);

    // debug!("Init: is sat? {:?}", solver_ctx.solver.check_sat().unwrap());

    // declare the variables and memory layouts
    func_constraints.iter().try_for_each(|(_, cons)| {
        let mut vairables = HashMap::new();
        cons.prf_preconditions.iter().for_each(|(awis, awi)| {
            awis.iter().for_each(|(e, _)| {
                vairables.extend(variables_in_expr(e).unwrap());
            });
            vairables.extend(variables_in_expr(&awi.0).unwrap());
        });
        cons.sem_assignments.iter().for_each(|a| {
            vairables.extend(variables_in_asgn(a).unwrap());
        });
        cons.prf_relationships.iter().for_each(|e| {
            vairables.extend(variables_in_expr(e).unwrap());
        });
        cons.sem_relationships.iter().for_each(|(e, _)| {
            vairables.extend(variables_in_expr(e).unwrap());
        });
        cons.assertions.iter().for_each(|(e, _)| {
            vairables.extend(variables_in_expr(e).unwrap());
        });
        // TODO?: branch conditions
        // println!("Variables extended");
        solver_ctx.lazy_declare(vairables)
    })?;

    // Iterate over basic blocks
    // This iteration includes bb-specific behaviors: branch state, phi functions, and stack memory de-alias.
    cfi.basic_blocks.iter().try_for_each(|(addr, bb)| {
        // declare phis
        solver_ctx.debug_info(&format!("Declaring phi functions for bb at {:x}", addr))?;
        let bb_info = ssa_sem.bb_map.get(addr).unwrap();

        // more than 1 predecessors: only one is taken
        if bb_info.predecessors.len() > 1 {
            let predecessors: Vec<SSExpr> = bb_info
                .predecessors
                .iter()
                .map(|pred| {
                    let sym = solver_ctx.declare_branch_cond(*pred, *addr).unwrap();
                    Const::new(Sort::Bool, sym).into()
                })
                .collect();
            let assertion = unify_ssexprs(&predecessors, boolean!("or"));
            solver_ctx.debug_info(&format!(
                "Asserting the branch conditions for bb at {:x}",
                addr
            ))?;
            solver_ctx.assume(&assertion)?;
        }

        solver_ctx.declare_phis(&bb_info.loc_phis, *addr)?;
        ssa_sem
            .ssa_map
            .range((Included(&bb.start), Included(&bb.end)))
            .try_for_each(|(addr, ins_ssa)| {
                solver_ctx.debug_info(&format!("Asserting the aliases at addr {:x}", addr))?;
                solver_ctx.assert_aliases(&ins_ssa.ssa)?;
                Ok(())
            })?;
        // println!("BB processed for addr {:x}", addr);
        Ok(())
    })?;

    // // Assert that only one of the successors of a BB can be true.
    // cfi.control_flow_graph.nodes().try_for_each(|node| {
    //     let successors = cfi.control_flow_graph.neighbors(node);
    //     let exprs: Vec<SSExpr> = successors.map(|s| {
    //         let sym = solver_ctx.declare_branch_cond(node, s).unwrap();
    //         SSExpr::Const(Sort::Bool, sym)
    //     }).collect();
    //     assert!(exprs.len() <= 2);
    //     let assertion = unify_br_conds_predtosuc(&exprs);
    //     solver_ctx.debug_info(&format!("Asserting the branch condition unification for bb at {:x}", node))?;
    //     solver_ctx.assume(&assertion)
    // })?;

    // assert the assignments
    ssa_sem.ssa_map.iter().try_for_each(|(addr, _)| {
        solver_ctx.debug_info(&format!("Assuming the assignments for addr {:x}", addr))?;
        solver_ctx.assign(&func_constraints.get(addr).unwrap().sem_assignments)
    })?;

    // println!("assignments asserted");

    // Prepare the relationships
    for (addr, ins_cons) in func_constraints {
        solver_ctx.debug_info(&format!("Solver preparing on addr 0x{:x}", addr))?;
        solver_ctx.debug_info(&format!("declaring the constants"))?;
        ins_cons
            .constants
            .iter()
            .try_for_each(|c| solver_ctx.do_declare(c))?;

        solver_ctx.debug_info(&format!("Assuming the assumptions"))?;
        solver_ctx.batch_assume(&ins_cons.sem_relationships)?;
    }
    // println!("relationships assumed");

    // Resolve constraints
    let mut temp_assertions: Vec<GenericExpr<Sub<GenericLocation<Sub<Register>>>>> = vec![];
    for (addr, ins_cons) in func_constraints {
        solver_ctx.debug_info(&format!("Solver asserting on addr 0x{:x}", addr))?;

        solver_ctx.debug_info(&format!("Verifying the precondition(s)"))?;
        solver_ctx.deal_preconditions(&ins_cons.prf_preconditions, &ins_cons.branch_conditions)?;
        // if ssa_sem.bb_map.contains_key(addr) {
        // let phi_map = &ssa_sem.bb_map.get(addr).unwrap().phis;
        // trace!("PhiMap at 0x{:X}: {:#?}", addr, phi_map);
        // }

        solver_ctx.debug_info(&format!("Asserting the relationships (policy checking)"))?;

        // To validate the relationships, we need to check that the model is satisfiable after making assumptions.
        solver_ctx.checked_assume(&ins_cons.prf_relationships)?;
        // solver_ctx.assert_sat()?;
        // debug!("assertions: {:#X?}", &constraints.assertions);
        if ins_cons.assertions.is_empty() {
            continue;
        } else {
            let ins_asserts: Vec<_> = ins_cons
                .assertions
                .iter()
                .map(|(assert, _)| assert.clone())
                .collect();
            temp_assertions.push(unify_ssexprs(&ins_asserts, boolean!("and")));
        }
    }
    // println!("all constraints added to temp_assertions");
    // #[cfg(not(debug_assertions))]
    // println!("length of the assertions: {}", temp_assertions.len());

    let unified_all_asserts = unify_ssexprs(&temp_assertions, boolean!("and"));
    if !solver_ctx.sandboxed_batch_check(
        &vec![(unified_all_asserts, "all asserts".to_string())],
        &vec![],
    )? {
        return Err(anyhow!("All assertion check: assertion failed"));
    }

    Ok(())
}
