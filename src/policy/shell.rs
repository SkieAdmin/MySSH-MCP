//! A small, conservative POSIX-shell parser. It does not execute anything; it only splits a command
//! line into simple commands (argv + redirections), pipelines, command substitutions and heredocs
//! so the policy engine can inspect every program that would run.

#[derive(Debug, Clone, Default)]
pub struct Redirect {
    pub op: String,
    pub target: String,
}

#[derive(Debug, Clone, Default)]
pub struct SimpleCmd {
    pub words: Vec<String>,
    pub redirects: Vec<Redirect>,
    pub pipeline: usize,
    pub pipe_pos: usize,
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub cmds: Vec<SimpleCmd>,
    /// Bodies of `$(...)`, `` `...` ``, `<(...)` and `>(...)`.
    pub substitutions: Vec<String>,
    pub heredoc_bodies: Vec<String>,
}

pub fn parse(input: &str) -> Parsed {
    let mut p = Parser {
        chars: input.chars().collect(),
        i: 0,
        out: Parsed::default(),
        cur: SimpleCmd::default(),
        word: String::new(),
        in_word: false,
        pending_redirect: None,
        pipeline: 0,
        pipe_pos: 0,
        heredocs: Vec::new(),
    };
    p.run();
    p.out
}

struct Parser {
    chars: Vec<char>,
    i: usize,
    out: Parsed,
    cur: SimpleCmd,
    word: String,
    in_word: bool,
    pending_redirect: Option<String>,
    pipeline: usize,
    pipe_pos: usize,
    heredocs: Vec<(String, bool)>,
}

impl Parser {
    fn peek(&self, k: usize) -> Option<char> {
        self.chars.get(self.i + k).copied()
    }

    fn len(&self) -> usize {
        self.chars.len()
    }

    fn finish_word(&mut self) {
        if !self.in_word {
            return;
        }
        let w = std::mem::take(&mut self.word);
        self.in_word = false;
        match self.pending_redirect.take() {
            Some(op) if op == "<<" || op == "<<-" => self.heredocs.push((w, op == "<<-")),
            Some(op) => self.cur.redirects.push(Redirect { op, target: w }),
            None => self.cur.words.push(w),
        }
    }

    fn finish_cmd(&mut self, pipe: bool) {
        self.finish_word();
        self.pending_redirect = None;
        if !self.cur.words.is_empty() || !self.cur.redirects.is_empty() {
            let mut c = std::mem::take(&mut self.cur);
            c.pipeline = self.pipeline;
            c.pipe_pos = self.pipe_pos;
            self.out.cmds.push(c);
        }
        if pipe {
            self.pipe_pos += 1;
        } else {
            self.pipeline += 1;
            self.pipe_pos = 0;
        }
    }

    fn run(&mut self) {
        while self.i < self.len() {
            let c = self.chars[self.i];
            match c {
                '\\' => {
                    match self.peek(1) {
                        Some('\n') => {}
                        Some(n) => {
                            self.word.push(n);
                            self.in_word = true;
                        }
                        None => {}
                    }
                    self.i += 2;
                }
                '\'' => {
                    self.in_word = true;
                    self.i += 1;
                    while self.i < self.len() && self.chars[self.i] != '\'' {
                        self.word.push(self.chars[self.i]);
                        self.i += 1;
                    }
                    self.i += 1;
                }
                '"' => {
                    self.in_word = true;
                    self.i += 1;
                    self.read_dquote();
                }
                '`' => {
                    self.in_word = true;
                    self.i += 1;
                    let s = self.read_backtick();
                    self.word.push('`');
                    self.word.push_str(&s);
                    self.word.push('`');
                    self.out.substitutions.push(s);
                }
                '$' => self.read_dollar(),
                ' ' | '\t' | '\r' => {
                    self.finish_word();
                    self.i += 1;
                }
                '\n' => {
                    self.finish_cmd(false);
                    self.i += 1;
                    self.consume_heredocs();
                }
                ';' => {
                    self.finish_cmd(false);
                    self.i += 1;
                }
                '&' => {
                    if self.peek(1) == Some('&') {
                        self.finish_cmd(false);
                        self.i += 2;
                    } else if self.peek(1) == Some('>') {
                        self.finish_word();
                        if self.peek(2) == Some('>') {
                            self.pending_redirect = Some("&>>".into());
                            self.i += 3;
                        } else {
                            self.pending_redirect = Some("&>".into());
                            self.i += 2;
                        }
                    } else {
                        self.finish_cmd(false);
                        self.i += 1;
                    }
                }
                '|' => {
                    if self.peek(1) == Some('|') {
                        self.finish_cmd(false);
                        self.i += 2;
                    } else {
                        self.finish_cmd(true);
                        self.i += if self.peek(1) == Some('&') { 2 } else { 1 };
                    }
                }
                '(' | ')' => {
                    self.finish_cmd(false);
                    self.i += 1;
                }
                '>' | '<' => self.read_redirect(c),
                '#' if !self.in_word => {
                    while self.i < self.len() && self.chars[self.i] != '\n' {
                        self.i += 1;
                    }
                }
                _ => {
                    self.word.push(c);
                    self.in_word = true;
                    self.i += 1;
                }
            }
        }
        self.finish_cmd(false);
    }

    fn read_dollar(&mut self) {
        self.in_word = true;
        match self.peek(1) {
            Some('(') => {
                self.i += 2;
                let s = self.read_balanced();
                self.word.push_str("$(");
                self.word.push_str(&s);
                self.word.push(')');
                self.out.substitutions.push(s);
            }
            Some('{') => {
                self.i += 2;
                let s = self.read_brace();
                self.word.push_str("${");
                self.word.push_str(&s);
                self.word.push('}');
            }
            Some('\'') => {
                // ANSI-C quoting: $'\x72\x6d' == "rm"
                self.i += 2;
                let mut raw = String::new();
                while self.i < self.len() {
                    let ch = self.chars[self.i];
                    if ch == '\\' && self.i + 1 < self.len() {
                        raw.push(ch);
                        raw.push(self.chars[self.i + 1]);
                        self.i += 2;
                        continue;
                    }
                    self.i += 1;
                    if ch == '\'' {
                        break;
                    }
                    raw.push(ch);
                }
                self.word.push_str(&decode_ansi_c(&raw));
            }
            _ => {
                self.word.push('$');
                self.i += 1;
            }
        }
    }

    fn read_dquote(&mut self) {
        while self.i < self.len() {
            let c = self.chars[self.i];
            match c {
                '"' => {
                    self.i += 1;
                    return;
                }
                '\\' => {
                    if let Some(n) = self.peek(1) {
                        match n {
                            '"' | '\\' | '$' | '`' => self.word.push(n),
                            '\n' => {}
                            _ => {
                                self.word.push('\\');
                                self.word.push(n);
                            }
                        }
                    }
                    self.i += 2;
                }
                '$' if self.peek(1) == Some('(') => {
                    self.i += 2;
                    let s = self.read_balanced();
                    self.word.push_str("$(");
                    self.word.push_str(&s);
                    self.word.push(')');
                    self.out.substitutions.push(s);
                }
                '$' if self.peek(1) == Some('{') => {
                    self.i += 2;
                    let s = self.read_brace();
                    self.word.push_str("${");
                    self.word.push_str(&s);
                    self.word.push('}');
                }
                '`' => {
                    self.i += 1;
                    let s = self.read_backtick();
                    self.word.push('`');
                    self.word.push_str(&s);
                    self.word.push('`');
                    self.out.substitutions.push(s);
                }
                _ => {
                    self.word.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// Read until the `)` matching an already-consumed `(`.
    fn read_balanced(&mut self) -> String {
        let mut depth = 1usize;
        let mut s = String::new();
        while self.i < self.len() {
            let c = self.chars[self.i];
            match c {
                '\\' => {
                    s.push(c);
                    if let Some(n) = self.peek(1) {
                        s.push(n);
                    }
                    self.i += 2;
                }
                '\'' | '"' => {
                    let quote = c;
                    s.push(c);
                    self.i += 1;
                    while self.i < self.len() && self.chars[self.i] != quote {
                        if quote == '"' && self.chars[self.i] == '\\' && self.i + 1 < self.len() {
                            s.push(self.chars[self.i]);
                            self.i += 1;
                        }
                        s.push(self.chars[self.i]);
                        self.i += 1;
                    }
                    if self.i < self.len() {
                        s.push(quote);
                        self.i += 1;
                    }
                }
                '(' => {
                    depth += 1;
                    s.push(c);
                    self.i += 1;
                }
                ')' => {
                    depth -= 1;
                    self.i += 1;
                    if depth == 0 {
                        return s;
                    }
                    s.push(c);
                }
                _ => {
                    s.push(c);
                    self.i += 1;
                }
            }
        }
        s
    }

    fn read_backtick(&mut self) -> String {
        let mut s = String::new();
        while self.i < self.len() {
            let c = self.chars[self.i];
            if c == '\\' && self.i + 1 < self.len() {
                s.push(self.chars[self.i + 1]);
                self.i += 2;
                continue;
            }
            self.i += 1;
            if c == '`' {
                return s;
            }
            s.push(c);
        }
        s
    }

    fn read_brace(&mut self) -> String {
        let mut depth = 1usize;
        let mut s = String::new();
        while self.i < self.len() {
            let c = self.chars[self.i];
            self.i += 1;
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return s;
                    }
                }
                _ => {}
            }
            s.push(c);
        }
        s
    }

    fn read_redirect(&mut self, c: char) {
        // Process substitution: <(...) or >(...)
        if self.peek(1) == Some('(') {
            self.in_word = true;
            self.i += 2;
            let s = self.read_balanced();
            self.word.push(c);
            self.word.push('(');
            self.word.push_str(&s);
            self.word.push(')');
            self.out.substitutions.push(s);
            return;
        }
        // "2>file": a pure number directly before the operator is a file descriptor.
        if self.in_word && !self.word.is_empty() && self.word.chars().all(|ch| ch.is_ascii_digit()) {
            self.word.clear();
            self.in_word = false;
        } else {
            self.finish_word();
        }
        let mut op = String::from(c);
        self.i += 1;
        if c == '>' {
            match self.peek(0) {
                Some('>') | Some('|') | Some('&') => {
                    op.push(self.chars[self.i]);
                    self.i += 1;
                }
                _ => {}
            }
        } else {
            match self.peek(0) {
                Some('<') => {
                    op.push('<');
                    self.i += 1;
                    match self.peek(0) {
                        Some('<') | Some('-') => {
                            op.push(self.chars[self.i]);
                            self.i += 1;
                        }
                        _ => {}
                    }
                }
                Some('>') | Some('&') => {
                    op.push(self.chars[self.i]);
                    self.i += 1;
                }
                _ => {}
            }
        }
        if op.ends_with('&') {
            // fd duplication: 2>&1, >&2, <&0, >&-
            let start = self.i;
            while let Some(ch) = self.peek(0) {
                if ch.is_ascii_digit() || ch == '-' {
                    self.i += 1;
                } else {
                    break;
                }
            }
            if self.i > start {
                return;
            }
            op = ">".into(); // `>&file` == redirect stdout+stderr to file
        }
        self.pending_redirect = Some(op);
    }

    fn consume_heredocs(&mut self) {
        let docs = std::mem::take(&mut self.heredocs);
        for (delim, strip_tabs) in docs {
            let mut body = String::new();
            while self.i < self.len() {
                let start = self.i;
                while self.i < self.len() && self.chars[self.i] != '\n' {
                    self.i += 1;
                }
                let line: String = self.chars[start..self.i].iter().collect();
                if self.i < self.len() {
                    self.i += 1;
                }
                let cmp = if strip_tabs { line.trim_start_matches('\t') } else { line.as_str() };
                if cmp.trim_end_matches('\r') == delim {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            self.out.heredoc_bodies.push(body);
        }
    }
}

/// Decode the escapes of a `$'...'` string (enough to defeat `$'\x72\x6d'`-style obfuscation).
fn decode_ansi_c(raw: &str) -> String {
    let c: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i] != '\\' || i + 1 >= c.len() {
            out.push(c[i]);
            i += 1;
            continue;
        }
        let e = c[i + 1];
        i += 2;
        match e {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'e' | 'E' => out.push('\x1b'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            'x' | 'u' | 'U' => {
                let max = match e {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let mut hex = String::new();
                while i < c.len() && hex.len() < max && c[i].is_ascii_hexdigit() {
                    hex.push(c[i]);
                    i += 1;
                }
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => {
                        out.push('\\');
                        out.push(e);
                        out.push_str(&hex);
                    }
                }
            }
            '0'..='7' => {
                let mut oct = String::from(e);
                while i < c.len() && oct.len() < 3 && ('0'..='7').contains(&c[i]) {
                    oct.push(c[i]);
                    i += 1;
                }
                match u32::from_str_radix(&oct, 8).ok().and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => out.push_str(&oct),
                }
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(input: &str) -> Vec<Vec<String>> {
        parse(input).cmds.into_iter().map(|c| c.words).collect()
    }

    #[test]
    fn splits_operators() {
        let w = words("cd /tmp && rm -rf ./build; ls | grep x || echo 'a b'");
        assert_eq!(w.len(), 5);
        assert_eq!(w[1], vec!["rm", "-rf", "./build"]);
        assert_eq!(w[4], vec!["echo", "a b"]);
    }

    #[test]
    fn quotes_join_words() {
        assert_eq!(words(r#"r''m -r"f" /"#)[0], vec!["rm", "-rf", "/"]);
        assert_eq!(words(r"\rm -rf /")[0], vec!["rm", "-rf", "/"]);
        assert_eq!(words(r"$'\x72\x6d' -rf /")[0], vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn redirects_and_fds() {
        let p = parse("echo hi > /etc/passwd 2>&1");
        assert_eq!(p.cmds[0].words, vec!["echo", "hi"]);
        assert_eq!(p.cmds[0].redirects.len(), 1);
        assert_eq!(p.cmds[0].redirects[0].target, "/etc/passwd");
    }

    #[test]
    fn substitutions_and_pipelines() {
        let p = parse("echo $(rm -rf /) `id` | bash");
        assert_eq!(p.substitutions, vec!["rm -rf /".to_string(), "id".to_string()]);
        assert_eq!(p.cmds[1].pipe_pos, 1);
        assert_eq!(p.cmds[1].pipeline, p.cmds[0].pipeline);
    }

    #[test]
    fn heredoc_body_is_not_a_command() {
        let p = parse("cat > /tmp/a.txt <<'EOF'\nrm -rf /\nEOF\necho done");
        assert_eq!(p.cmds.len(), 2);
        assert_eq!(p.cmds[1].words, vec!["echo", "done"]);
        assert_eq!(p.heredoc_bodies, vec!["rm -rf /\n".to_string()]);
    }
}
