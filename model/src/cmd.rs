use crate::protocol::Cmd;

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

