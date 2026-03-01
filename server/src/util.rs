use securefs_model::protocol::FNode;

/// Resolve a user input path relative to the current working directory.
pub fn resolve_path(current: &str, input: &str) -> String {
    if input.starts_with('/') {
        normalize_path(input.to_string())
    } else {
        normalize_path(format!("{}/{}", current, input))
    }
}

/// Normalize path components by collapsing `.` and `..`.
pub fn normalize_path(path: String) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        } else if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Check that a resolved path is safely within /home and contains no dangerous bytes.
pub fn is_safe_path(path: &str) -> bool {
    let under_home = path == "/home" || path.starts_with("/home/");
    let no_null = !path.contains('\0');
    let depth = path.split('/').filter(|s| !s.is_empty()).count();
    let sane_depth = depth <= 64;
    under_home && no_null && sane_depth
}

/// Format ls entry with owner, group, permissions, and name.
pub fn format_ls_entry(node: &FNode) -> String {
    let suffix = if node.dir { "/" } else { "" };
    let perms = format_permissions(node.u, node.g, node.o);
    format!("{} {} {}{}", node.owner, perms, node.name, suffix)
}

/// Format Unix-style permissions into rwxrwxrwx string.
pub fn format_permissions(u: i16, g: i16, o: i16) -> String {
    let mut perms = String::new();
    perms.push(if u & 0b100 != 0 { 'r' } else { '-' });
    perms.push(if u & 0b010 != 0 { 'w' } else { '-' });
    perms.push(if u & 0b001 != 0 { 'x' } else { '-' });
    perms.push(if g & 0b100 != 0 { 'r' } else { '-' });
    perms.push(if g & 0b010 != 0 { 'w' } else { '-' });
    perms.push(if g & 0b001 != 0 { 'x' } else { '-' });
    perms.push(if o & 0b100 != 0 { 'r' } else { '-' });
    perms.push(if o & 0b010 != 0 { 'w' } else { '-' });
    perms.push(if o & 0b001 != 0 { 'x' } else { '-' });
    perms
}

/// Check if the current user can read the node (owner/other only, no group check).
#[cfg(test)]
pub fn can_read(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        if node.owner == *u && (node.u & 0b100) != 0 {
            return true;
        }
    }
    (node.o & 0b100) != 0
}

/// Check if the current user can write the node (owner/other only, no group check).
#[cfg(test)]
pub fn can_write(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        if node.owner == *u && (node.u & 0b010) != 0 {
            return true;
        }
    }
    (node.o & 0b010) != 0
}

/// Check if the current user can read the node with full group permission support.
pub fn can_read_with_group(
    node: &FNode,
    user: Option<&String>,
    user_group: Option<&String>,
    owner_group: Option<&String>,
) -> bool {
    if let Some(u) = user {
        if node.owner == *u && (node.u & 0b100) != 0 {
            return true;
        }
        if let (Some(ug), Some(og)) = (user_group, owner_group) {
            if ug == og && (node.g & 0b100) != 0 {
                return true;
            }
        }
    }
    (node.o & 0b100) != 0
}

/// Check if the current user can write the node with full group permission support.
pub fn can_write_with_group(
    node: &FNode,
    user: Option<&String>,
    user_group: Option<&String>,
    owner_group: Option<&String>,
) -> bool {
    if let Some(u) = user {
        if node.owner == *u && (node.u & 0b010) != 0 {
            return true;
        }
        if let (Some(ug), Some(og)) = (user_group, owner_group) {
            if ug == og && (node.g & 0b010) != 0 {
                return true;
            }
        }
    }
    (node.o & 0b010) != 0
}

/// Check if the current user can execute the node.
#[cfg(test)]
pub fn can_execute(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        if node.owner == *u && (node.u & 0b001) != 0 {
            return true;
        }
    }
    (node.o & 0b001) != 0
}

/// Check if the current user can execute the node with full group permission support.
#[allow(dead_code)]
pub fn can_execute_with_group(
    node: &FNode,
    user: Option<&String>,
    user_group: Option<&String>,
    owner_group: Option<&String>,
) -> bool {
    if let Some(u) = user {
        if node.owner == *u && (node.u & 0b001) != 0 {
            return true;
        }
        if let (Some(ug), Some(og)) = (user_group, owner_group) {
            if ug == og && (node.g & 0b001) != 0 {
                return true;
            }
        }
    }
    (node.o & 0b001) != 0
}

/// Check if the current user is the owner of the node.
pub fn is_owner(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        return node.owner == *u;
    }
    false
}

/// Get the current Unix timestamp in seconds.
pub fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validate file or directory name (no path separators or special chars).
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\0') && name != "." && name != ".."
}

/// Validate username or group name (alphanumeric + underscore/hyphen).
pub fn is_valid_user_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        && name.chars().next().is_some_and(|c| c.is_alphabetic())
}

/// Validate password strength (minimum 8 characters).
pub fn is_valid_password(pass: &str) -> bool {
    pass.len() >= 8
}
