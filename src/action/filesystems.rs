// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use rrg_proto::{Filesystem, KeyValue, AttributedDict, DataBlob};
use crate::session::{self, Session};

pub struct Response {
    mount_info: proc_mounts::MountInfo,
}

pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    for mount_info in proc_mounts::MountIter::new().unwrap() {
        session.reply(Response {
            mount_info: mount_info.unwrap(),
        })?;
    }
    Ok(())
}

fn option_to_key_value(option: String) -> KeyValue {
    match &option.split('=').collect::<Vec<&str>>()[..] {
        &[key] => {
            KeyValue {
                k: Some(DataBlob {
                    string: Some(String::from(key)),
                    ..Default::default()
                }),
                v: None,
            }
        },
        &[key, value] => {
            KeyValue {
                k: Some(DataBlob {
                    string: Some(String::from(key)),
                    ..Default::default()
                }),
                v: Some(DataBlob {
                    string: Some(String::from(value)),
                    ..Default::default()
                }),
            }
        },
        _ => {
            // This is impossible.
            panic!("Bad mount option")
        },
    }
}

fn options_to_dict(options: Vec<String>) -> AttributedDict {
    AttributedDict {
        dat: options.into_iter().map(option_to_key_value).collect(),
    }
}

impl super::Response for Response {
    const RDF_NAME: Option<&'static str> = Some("Filesystem");

    type Proto = rrg_proto::Filesystem;

    fn into_proto(self) -> Filesystem {
        // TODO: remove lossy conversion of PathBuf to String
        //   when mount_point field of Filesystem message
        //   will have bytes type instead of string.
        Filesystem {
            device: Some(self.mount_info.source.into_os_string()
                .into_string().unwrap_or_default()),
            mount_point: Some(self.mount_info.dest.into_os_string()
                .into_string().unwrap_or_default()),
            r#type: Some(self.mount_info.fstype),
            label: None,
            options: Some(options_to_dict(self.mount_info.options)),
        }
    }
}
