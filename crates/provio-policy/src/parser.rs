//! Recursive-descent parser for the `when` DSL.
//!
//! Grammar (spec §7):
//!   or-expr   = and-expr ("or" and-expr)*
//!   and-expr  = unary ("and" unary)*
//!   unary     = "not" unary | "(" or-expr ")" | predicate
//!   predicate = field op value | field "in" listref
//!   op        = "==" | "!=" | "startswith" | "endswith" | "contains" | "matches"
//!   value     = '"' ... '"'   (string literal, regex escapes pass through)
//!   listref   = ident ("." ident)*   (e.g. hosts.allowed)
//!
//! This parser consumes untrusted policy text on the security path: it never
//! panics and reports every error with a column offset.

use crate::ast::{Field, RawExpr, RawOp, RawPredicate};

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    EqEq,
    Ne,
    LParen,
    RParen,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            src: src.as_bytes(),
            pos: 0,
        }
    }

    fn err(&self, msg: &str) -> String {
        format!("column {}: {}", self.pos + 1, msg)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && (self.src[self.pos] as char).is_whitespace() {
            self.pos += 1;
        }
    }

    fn next(&mut self) -> Result<Option<Tok>, String> {
        self.skip_ws();
        if self.pos >= self.src.len() {
            return Ok(None);
        }
        let c = self.src[self.pos] as char;
        match c {
            '(' => {
                self.pos += 1;
                Ok(Some(Tok::LParen))
            }
            ')' => {
                self.pos += 1;
                Ok(Some(Tok::RParen))
            }
            '=' => {
                if self.src.get(self.pos + 1) == Some(&b'=') {
                    self.pos += 2;
                    Ok(Some(Tok::EqEq))
                } else {
                    Err(self.err("expected \"==\" (bare \"=\" is not an operator)"))
                }
            }
            '!' => {
                if self.src.get(self.pos + 1) == Some(&b'=') {
                    self.pos += 2;
                    Ok(Some(Tok::Ne))
                } else {
                    Err(self.err("expected \"!=\" (use \"not\" for negation)"))
                }
            }
            '"' => self.string().map(Some),
            // Identifiers must start with a letter or underscore; digits are
            // valid only inside. Keeps `tool in 42` a parse error.
            _ if c.is_alphabetic() || c == '_' => Ok(Some(self.ident())),
            _ => Err(self.err(&format!("unexpected character {:?}", c))),
        }
    }

    /// Double-quoted string literal. `\"`, `\\`, `\n`, `\t`, `\r` are
    /// decoded; any OTHER backslash sequence (e.g. `\.`) passes through
    /// untouched so regex patterns survive intact.
    fn string(&mut self) -> Result<Tok, String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            if self.pos >= self.src.len() {
                return Err(self.err("unterminated string literal"));
            }
            let c = self.src[self.pos] as char;
            self.pos += 1;
            match c {
                '"' => return Ok(Tok::Str(out)),
                '\\' => {
                    if self.pos >= self.src.len() {
                        return Err(self.err("unterminated escape at end of string"));
                    }
                    let e = self.src[self.pos] as char;
                    self.pos += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        other => {
                            out.push('\\');
                            out.push(other);
                        }
                    }
                }
                _ => out.push(c),
            }
        }
    }

    fn ident(&mut self) -> Tok {
        let start = self.pos;
        while self.pos < self.src.len() {
            let c = self.src[self.pos] as char;
            if c.is_alphanumeric() || matches!(c, '_' | '.' | '-') {
                self.pos += 1;
            } else {
                break;
            }
        }
        Tok::Ident(String::from_utf8_lossy(&self.src[start..self.pos]).into_owned())
    }
}

/// Parse a `when` expression string into a raw AST.
pub fn parse_when(src: &str) -> Result<RawExpr, String> {
    let mut lexer = Lexer::new(src);
    let mut toks = Vec::new();
    while let Some(tok) = lexer.next()? {
        toks.push(tok);
    }
    if toks.is_empty() {
        return Err("empty `when` expression".to_string());
    }
    let mut p = Parser { toks, pos: 0 };
    let expr = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err(format!("unexpected trailing token {:?}", p.toks[p.pos]));
    }
    Ok(expr)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat_keyword(&mut self, kw: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Ident(w)) if w == kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<RawExpr, String> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Ident(w)) if w == "or") {
            self.pos += 1;
            let rhs = self.parse_and()?;
            lhs = RawExpr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<RawExpr, String> {
        let mut lhs = self.parse_unary()?;
        while matches!(self.peek(), Some(Tok::Ident(w)) if w == "and") {
            self.pos += 1;
            let rhs = self.parse_unary()?;
            lhs = RawExpr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<RawExpr, String> {
        if self.eat_keyword("not") {
            let inner = self.parse_unary()?;
            return Ok(RawExpr::Not(Box::new(inner)));
        }
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.pos += 1;
            let inner = self.parse_or()?;
            return match self.bump() {
                Some(Tok::RParen) => Ok(inner),
                other => Err(format!("expected \")\" but found {:?}", other)),
            };
        }
        self.parse_predicate()
    }

    fn parse_predicate(&mut self) -> Result<RawExpr, String> {
        let field = match self.bump() {
            Some(Tok::Ident(name)) => Field::from_name(&name),
            other => {
                return Err(format!(
                    "expected a field name (tool, command, path, url.host, query, agent, mode, server, server.trust) but found {:?}",
                    other
                ))
            }
        };
        // Membership: field in list.ref
        if self.eat_keyword("in") {
            return match self.bump() {
                Some(Tok::Ident(list_ref)) => Ok(RawExpr::Pred(RawPredicate::In { field, list_ref })),
                other => Err(format!(
                    "expected a named list reference (e.g. hosts.allowed) after \"in\" but found {:?}",
                    other
                )),
            };
        }
        let op = match self.bump() {
            Some(Tok::EqEq) => "eq",
            Some(Tok::Ne) => "ne",
            Some(Tok::Ident(w)) => match w.as_str() {
                "startswith" => "startswith",
                "endswith" => "endswith",
                "contains" => "contains",
                "matches" => "matches",
                other => {
                    return Err(format!(
                        "unknown operator {:?} (expected ==, !=, startswith, endswith, contains, matches, in)",
                        other
                    ))
                }
            },
            other => {
                return Err(format!(
                    "expected an operator (==, !=, startswith, endswith, contains, matches, in) but found {:?}",
                    other
                ))
            }
        };
        let value = match self.bump() {
            Some(Tok::Str(v)) => v,
            other => {
                return Err(format!(
                    "expected a double-quoted string value but found {:?}",
                    other
                ))
            }
        };
        let op = match op {
            "eq" => RawOp::Eq(value),
            "ne" => RawOp::Ne(value),
            "startswith" => RawOp::StartsWith(value),
            "endswith" => RawOp::EndsWith(value),
            "contains" => RawOp::Contains(value),
            _ => RawOp::Matches(value),
        };
        Ok(RawExpr::Pred(RawPredicate::Compare { field, op }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pred(field: Field, op: RawOp) -> RawExpr {
        RawExpr::Pred(RawPredicate::Compare { field, op })
    }

    #[test]
    fn parses_simple_comparison() {
        let e = parse_when("tool == \"bash\"").unwrap();
        assert_eq!(e, pred(Field::Tool, RawOp::Eq("bash".into())));
    }

    #[test]
    fn and_binds_tighter_than_or() {
        let e = parse_when("a == \"1\" or b == \"2\" and c == \"3\"").unwrap();
        match e {
            RawExpr::Or(l, r) => {
                assert_eq!(*l, pred(Field::Unknown, RawOp::Eq("1".into())));
                assert!(matches!(*r, RawExpr::And(_, _)));
            }
            other => panic!("expected or at root, got {:?}", other),
        }
    }

    #[test]
    fn not_applies_to_following_unary() {
        let e = parse_when("not url.host in hosts.allowed").unwrap();
        match e {
            RawExpr::Not(inner) => assert!(matches!(
                *inner,
                RawExpr::Pred(RawPredicate::In {
                    field: Field::UrlHost,
                    ..
                })
            )),
            other => panic!("expected not, got {:?}", other),
        }
    }

    #[test]
    fn parses_parens_and_aliases() {
        let e = parse_when(
            "(server.trust == \"malicious\" or tool startswith \"postgres\") and not mode == \"mcp\"",
        )
        .unwrap();
        assert!(matches!(e, RawExpr::And(_, _)));
    }

    #[test]
    fn regex_escapes_pass_through_strings() {
        let e = parse_when("path matches \"\\\\.env|id_rsa$\"").unwrap();
        assert_eq!(
            e,
            pred(Field::Path, RawOp::Matches("\\.env|id_rsa$".into()))
        );
    }

    #[test]
    fn rejects_garbage_without_panic() {
        for bad in [
            "",
            "tool = \"bash\"",
            "tool == ",
            "tool == bash",
            "(tool == \"bash\"",
            "tool =! \"bash\"",
            "and tool == \"bash\"",
            "tool == \"bash\" and",
            "not",
            "tool in 42",
        ] {
            assert!(parse_when(bad).is_err(), "expected error for {:?}", bad);
        }
    }
}
