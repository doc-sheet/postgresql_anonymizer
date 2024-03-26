///
/// # Regular Expressions
///
///
use core::ffi::CStr;
use regex::Regex;


//----------------------------------------------------------------------------
// Matches
//----------------------------------------------------------------------------

pub fn is_match_indirect_identifier(haystack: &CStr) -> bool {
    let re = Regex::new(r"(?is)^ *(QUASI|INDIRECT) +IDENTIFIER *$").unwrap();
    re.is_match(haystack.to_str().unwrap())
}

pub fn is_match_masked(haystack: &CStr) -> bool {
    let re = Regex::new(r"(?is)^ *MASKED *$").unwrap();
    re.is_match(haystack.to_str().unwrap())
}

pub fn is_match_not_masked(haystack: &CStr) -> bool {
    let re = Regex::new(r"(?is)^ *NOT +MASKED *$").unwrap();
    re.is_match(haystack.to_str().unwrap())
}

pub fn is_match_tablesample(haystack: &CStr) -> bool {
    let re = Regex::new(r"(?is)^ *TABLESAMPLE +(.*) *$").unwrap();
    re.is_match(haystack.to_str().unwrap())
}

pub fn is_match_trusted(haystack: &CStr) -> bool {
    let re = Regex::new(r"(?is)^ *TRUSTED *$").unwrap();
    re.is_match(haystack.to_str().unwrap())
}

//----------------------------------------------------------------------------
// Captures
//----------------------------------------------------------------------------
fn capture_first(re: Regex, haystack: &CStr) -> Option<&str> {
    let caps = re.captures(haystack.to_str().expect("haystack should be valid"));
    if let Some(c) = caps {
        return Some(c.get(1).unwrap().as_str());
    }
    None
}

pub fn capture_function(haystack: &CStr) -> Option<&str> {
    let re = Regex::new(r"(?is)^ *MASKED +WITH +FUNCTION +(.*) *$").unwrap();
    capture_first(re,haystack)
}

pub fn capture_value(haystack: &CStr) -> Option<&str> {
    let re = Regex::new(r"(?is)^ *MASKED +WITH +VALUE +(.*) *$").unwrap();
    capture_first(re,haystack)
}

#[cfg(test)]
mod tests {
    use c_str_macro::c_str;

    #[test]
    fn test_re_indirect_identifier() {
        use crate::re::is_match_indirect_identifier;
        assert!(is_match_indirect_identifier(c_str!("INDIRECT IDENTIFIER")));
        assert!(is_match_indirect_identifier(c_str!("quasi identifier")));
        assert!(is_match_indirect_identifier(c_str!(" QuAsI    idenTIFIER  ")));
        assert!(!is_match_indirect_identifier(c_str!("IDENTIFIER")));
        assert!(!is_match_indirect_identifier(c_str!("quasi-identifier")));
    }

    #[test]
    fn test_regex_masked() {
        use crate::re::is_match_masked;
        assert!(is_match_masked(c_str!("MASKED")));
        assert!(is_match_masked(c_str!("  MaSKeD       ")));
        assert!(!is_match_masked(c_str!("MAKSED")));
    }

    #[test]
    fn test_regex_masked_with_function() {
        use crate::re::capture_function;
        assert!(capture_function(c_str!("MASKED WITH FUNCTION public.foo()")).is_some());
        assert!(capture_function(c_str!(" masked  WITH funCTION bar(0,$$y$$) ")).is_some());
        assert!(capture_function(c_str!(" masked  WITH funCTION bar(0,
                                                                    $$y$$) ")).is_some());
        assert!(!capture_function(c_str!("MASKED WITH FUNCTION")).is_some());
        assert!(!capture_function(c_str!("MASKED WITH public.foo()")).is_some());
    }

    #[test]
    fn test_regex_masked_with_value() {
        use crate::re::capture_value;
        assert!(capture_value(c_str!("MASKED WITH VALUE $$zero$$")).is_some());
        assert!(capture_value(c_str!(" masked  WITH vaLue  NULL ")).is_some());
        assert!(!capture_value(c_str!("MASKED WITH VALUE")).is_some());
        assert!(!capture_value(c_str!("MASKED WITH 0")).is_some());
    }
    #[test]
    fn test_re_not_masked() {
        use crate::re::is_match_not_masked;
        assert!(is_match_not_masked(c_str!("NOT MASKED")));
        assert!(is_match_not_masked(c_str!("NOT    MASKED")));
        assert!(is_match_not_masked(c_str!("not masked")));
        assert!(is_match_not_masked(c_str!(" NoT MaSkED ")));
        assert!(is_match_not_masked(c_str!(" NoT MaSkED ")));
        assert!(!is_match_not_masked(c_str!("NOTMASKED")));
    }

    #[test]
    fn test_re_tablesample() {
        use crate::re::is_match_tablesample;
        assert!(is_match_tablesample(c_str!("TABLESAMPLE SYSTEM(10)")));
        assert!(is_match_tablesample(c_str!(" tablesample  sySTEM(10)")));
        assert!(!is_match_tablesample(c_str!("TABLESAMPLE")));
    }

    #[test]
    fn test_re_trusted() {
        use crate::re::is_match_trusted;
        assert!(is_match_trusted(c_str!("TRUSTED")));
        assert!(is_match_trusted(c_str!("     trusted ")));
        assert!(!is_match_trusted(c_str!("TRUSTTED")));
    }

}
