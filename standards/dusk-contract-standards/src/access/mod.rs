// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Access-control modules.

pub mod access_control;
pub mod events;
pub mod ownable;
pub mod owner_set;
pub mod pausable;

pub use access_control::{AccessControl, Role, DEFAULT_ADMIN_ROLE};
pub use ownable::{Ownable, Ownable2Step};
pub use owner_set::OwnerSet;
pub use pausable::Pausable;
