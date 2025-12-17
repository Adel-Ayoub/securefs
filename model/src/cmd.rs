//! Helpers for mapping string input into protocol commands and validating arity.

use crate::protocol::Cmd;

/// Convert strings into strongly typed commands.
pub trait MapStr: Sized {
    fn from_str(s: String) -> Result<Self, ()>;
}

impl MapStr for Cmd {
    fn from_str(s: String) -> Result<Self, ()> {
        match s.to_lowercase().as_str() {
            "cat" => Ok(Cmd::Cat),
            "cd" => Ok(Cmd::Cd),
            "echo" => Ok(Cmd::Echo),
            "delete" => Ok(Cmd::Delete),
            "login" => Ok(Cmd::Login),
            "get_encrypted_filename" => Ok(Cmd::GetEncryptedFile),
            "ls" => Ok(Cmd::Ls),
            "mkdir" => Ok(Cmd::Mkdir),
            "mv" => Ok(Cmd::Mv),
            "chmod" => Ok(Cmd::Chmod),
            "scan" => Ok(Cmd::Scan),
            "new_connection" => Ok(Cmd::NewConnection),
            "new_user" => Ok(Cmd::NewUser),
            "new_group" => Ok(Cmd::NewGroup),
            "failure" => Ok(Cmd::Failure),
            "pwd" => Ok(Cmd::Pwd),
            "touch" => Ok(Cmd::Touch),
            "logout" => Ok(Cmd::Logout),
            _ => Err(()),
        }
    }
}

/// Return the expected argument count for a command string.
pub trait NumArgs {
    fn num_args(s: String) -> Result<usize, ()>;
}

impl NumArgs for Cmd {
    fn num_args(s: String) -> Result<usize, ()> {
        match s.to_lowercase().as_str() {
            "cat" => Ok(2),
            "cd" => Ok(2),
            "echo" => Ok(usize::MAX),
            "login" => Ok(2),
            "get_encrypted_filename" => Ok(usize::MAX),
            "ls" => Ok(1),
            "mkdir" => Ok(2),
            "mv" => Ok(3),
            "delete" => Ok(2),
            "chmod" => Ok(3),
            "scan" => Ok(usize::MAX),
            "new_connection" => Ok(usize::MAX),
            "new_user" => Ok(3),
            "new_group" => Ok(2),
            "failure" => Ok(usize::MAX),
            "pwd" => Ok(1),
            "touch" => Ok(2),
            "logout" => Ok(1),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_str_valid_commands() {
        assert_eq!(Cmd::from_str("ls".into()).unwrap(), Cmd::Ls);
        assert_eq!(Cmd::from_str("cd".into()).unwrap(), Cmd::Cd);
        assert_eq!(Cmd::from_str("pwd".into()).unwrap(), Cmd::Pwd);
        assert_eq!(Cmd::from_str("mkdir".into()).unwrap(), Cmd::Mkdir);
        assert_eq!(Cmd::from_str("touch".into()).unwrap(), Cmd::Touch);
        assert_eq!(Cmd::from_str("cat".into()).unwrap(), Cmd::Cat);
        assert_eq!(Cmd::from_str("echo".into()).unwrap(), Cmd::Echo);
        assert_eq!(Cmd::from_str("mv".into()).unwrap(), Cmd::Mv);
        assert_eq!(Cmd::from_str("delete".into()).unwrap(), Cmd::Delete);
        assert_eq!(Cmd::from_str("chmod".into()).unwrap(), Cmd::Chmod);
        assert_eq!(Cmd::from_str("scan".into()).unwrap(), Cmd::Scan);
        assert_eq!(Cmd::from_str("login".into()).unwrap(), Cmd::Login);
        assert_eq!(Cmd::from_str("logout".into()).unwrap(), Cmd::Logout);
    }

    #[test]
    fn test_map_str_case_insensitive() {
        assert_eq!(Cmd::from_str("LS".into()).unwrap(), Cmd::Ls);
        assert_eq!(Cmd::from_str("Pwd".into()).unwrap(), Cmd::Pwd);
        assert_eq!(Cmd::from_str("CHMOD".into()).unwrap(), Cmd::Chmod);
    }

    #[test]
    fn test_map_str_invalid() {
        assert!(Cmd::from_str("invalid_cmd".into()).is_err());
        assert!(Cmd::from_str("".into()).is_err());
        assert!(Cmd::from_str("cp".into()).is_err());
    }

    #[test]
    fn test_num_args() {
        assert_eq!(Cmd::num_args("ls".into()).unwrap(), 1);
        assert_eq!(Cmd::num_args("cd".into()).unwrap(), 2);
        assert_eq!(Cmd::num_args("mkdir".into()).unwrap(), 2);
        assert_eq!(Cmd::num_args("mv".into()).unwrap(), 3);
        assert_eq!(Cmd::num_args("chmod".into()).unwrap(), 3);
        assert_eq!(Cmd::num_args("echo".into()).unwrap(), usize::MAX);
        assert!(Cmd::num_args("invalid".into()).is_err());
    }
}

