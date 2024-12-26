// src/auth_bsdauth.rs

use std::fmt;

// 定义 AuthSession trait，并要求实现 Debug
pub trait AuthSession: fmt::Debug {
    fn get_challenge(&self) -> Option<String>;
    fn set_challenge(&mut self, challenge: String);
}

// 为 SimpleAuthSession 实现 AuthSession trait
#[derive(Debug)] // 这里使用 #[derive(Debug)] 自动为 SimpleAuthSession 实现 Debug
pub struct SimpleAuthSession {
    pub challenge: Option<String>,
}

impl AuthSession for SimpleAuthSession {
    fn get_challenge(&self) -> Option<String> {
        self.challenge.clone()
    }

    fn set_challenge(&mut self, challenge: String) {
        self.challenge = Some(challenge);
    }
}

// 认证上下文结构体
#[derive(Debug)]
pub struct Authctxt {
    pub user: String,
    pub style: Option<String>,
    pub valid: bool,
    pub as_session: Option<Box<dyn AuthSession>>, // 使用 trait 对象进行动态分发
}

impl Authctxt {
    pub fn new(user: String) -> Self {
        Authctxt {
            user,
            style: None,
            valid: true,
            as_session: None,
        }
    }
}

// 认证上下文的相关操作
pub fn bsdauth_init_ctx(authctxt: &mut Authctxt) -> &mut Authctxt {
    authctxt
}

pub fn bsdauth_query(
    ctx: &mut Authctxt,
    name: &mut String,
    infotxt: &mut String,
    numprompts: &mut u32,
    prompts: &mut Vec<String>,
    echo_on: &mut Vec<u32>,
) -> i32 {
    let mut challenge = None;

    // 如果有现有的挑战，则复用
    if let Some(session) = &ctx.as_session {
        if let Some(ch) = &session.get_challenge() {
            challenge = Some(ch.clone());
        }
    }

    // 如果没有现有的挑战，则创建一个新的
    if challenge.is_none() {
        challenge = Some("new-challenge".to_string()); // Placeholder challenge
    }

    if let Some(challenge) = challenge {
        *name = String::new();
        *infotxt = String::new();
        *numprompts = 1;
        *prompts = vec![challenge];
        *echo_on = vec![0];
        return 0;
    }

    -1
}

pub fn bsdauth_respond(ctx: &mut Authctxt, numresponses: u32, responses: Vec<String>) -> i32 {
    if !ctx.valid {
        return -1;
    }

    if ctx.as_session.is_none() {
        eprintln!("bsdauth_respond: no bsd auth session");
        return -1;
    }

    if numresponses != 1 {
        return -1;
    }

    // 认证逻辑
    let authok = if let Some(session) = &ctx.as_session {
        if let Some(challenge) = &session.get_challenge() {
            responses[0] == *challenge // 解引用 challenge
        } else {
            false
        }
    } else {
        false
    };

    ctx.as_session = None; // 认证后清除会话

    if authok {
        0
    } else {
        -1
    }
}

pub fn bsdauth_free_ctx(ctx: &mut Authctxt) {
    if let Some(session) = &mut ctx.as_session {
        // 释放会话
        session.set_challenge("".to_string());
    }
}

pub struct KbdintDevice {
    pub name: &'static str,
    pub init_ctx: fn(&mut Authctxt) -> &mut Authctxt,
    pub query: fn(
        &mut Authctxt,
        &mut String,
        &mut String,
        &mut u32,
        &mut Vec<String>,
        &mut Vec<u32>,
    ) -> i32,
    pub respond: fn(&mut Authctxt, u32, Vec<String>) -> i32,
    pub free_ctx: fn(&mut Authctxt),
}

pub static BSDAUTH_DEVICE: KbdintDevice = KbdintDevice {
    name: "bsdauth",
    init_ctx: bsdauth_init_ctx,
    query: bsdauth_query,
    respond: bsdauth_respond,
    free_ctx: bsdauth_free_ctx,
};
