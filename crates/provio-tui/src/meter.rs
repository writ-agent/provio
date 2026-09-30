//! Cost and token meter across providers (spec §12: cheap to build,
//! consistently loved). Prices are CONFIG DATA, not claims — operators set
//! their own via `provio.toml`/flags as providers change pricing.

use std::collections::BTreeMap;

/// USD per 1M tokens: (input, output).
#[derive(Debug, Clone, Copy)]
pub struct Pricing {
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
}

impl Default for TokenMeter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TokenMeter {
    /// model -> (input tokens, output tokens)
    usage: BTreeMap<String, (u64, u64)>,
    /// model -> pricing; missing models are counted but priced at unknown.
    pricing: BTreeMap<String, Pricing>,
}

impl TokenMeter {
    pub fn new() -> Self {
        TokenMeter {
            usage: BTreeMap::new(),
            pricing: BTreeMap::new(),
        }
    }

    pub fn set_pricing(&mut self, model: &str, p: Pricing) {
        self.pricing.insert(model.to_string(), p);
    }

    pub fn add_usage(&mut self, model: &str, input: u64, output: u64) {
        let e = self.usage.entry(model.to_string()).or_insert((0, 0));
        e.0 += input;
        e.1 += output;
    }

    /// None when the model has no configured price (never invent a number).
    pub fn cost_usd(&self, model: &str) -> Option<f64> {
        let (i, o) = self.usage.get(model)?;
        let p = self.pricing.get(model)?;
        Some((*i as f64 * p.input_per_mtok + *o as f64 * p.output_per_mtok) / 1_000_000.0)
    }

    pub fn render(&self) -> String {
        let mut out = String::from("model                tokens (in/out)      cost");
        for (model, (i, o)) in &self.usage {
            let cost = self
                .cost_usd(model)
                .map(|c| format!("${c:.4}"))
                .unwrap_or_else(|| "n/a (no price configured)".into());
            out.push_str(&format!("\n{model:<20} {i:>10} / {o:<10} {cost}"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn costs_and_unknown_prices() {
        let mut m = TokenMeter::new();
        m.set_pricing(
            "example-model",
            Pricing {
                input_per_mtok: 3.0,
                output_per_mtok: 15.0,
            },
        );
        m.add_usage("example-model", 1_000_000, 100_000);
        m.add_usage("unpriced-model", 5, 5);
        assert_eq!(m.cost_usd("example-model"), Some(4.5));
        assert_eq!(m.cost_usd("unpriced-model"), None);
        let r = m.render();
        assert!(r.contains("example-model"));
        assert!(r.contains("no price configured"));
    }
}
