use std::fs::File;

use serde_json::json;

use adlt::{
    dlt::{DltMessage, DltMessageIndexType, DLT_MAX_STORAGE_MSG_SIZE},
    plugins::{
        muniic::MuniicPlugin,
        plugin::{Plugin, TreeItem},
    },
    utils::{
        get_dlt_message_iterator, sorting_multi_readeriterator::SequentialMultiIterator,
        LowMarkBufReader,
    },
};
use criterion::{criterion_group, criterion_main, Criterion};

// todo move to utils (and remove from lifecycle/mod.rs)
fn get_file_iterator(file_name: &str, namespace: u32) -> Box<dyn Iterator<Item = DltMessage>> {
    let fi = File::open(file_name).unwrap();
    const BUFREADER_CAPACITY: usize = 512 * 1024;
    let buf_reader = LowMarkBufReader::new(fi, BUFREADER_CAPACITY, DLT_MAX_STORAGE_MSG_SIZE);
    let it = get_dlt_message_iterator(
        std::path::Path::new(file_name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or(""),
        0,
        buf_reader,
        namespace,
        None,
        None,
        None,
    );
    it
}

fn parse_example_dlt() {
    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests");
    test_dir.push("muniic");
    test_dir.push("muniic.dlt");
    let file_name = test_dir.to_string_lossy();
    let binding = [file_name];
    let its = binding
        .iter()
        .map(|file_name| get_file_iterator(file_name, 0));
    let mut it = SequentialMultiIterator::new_or_single_it(0, its);

    let mut test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests");
    test_dir.push("muniic");
    let config = json!({"name":"Muniic", "enabled":true, "jsonDir":test_dir});
    match MuniicPlugin::from_json(config.as_object().unwrap()) {
        Ok(mut plugin) => {
            let mut messages_processed: DltMessageIndexType = 0;
            for mut msg in it.by_ref() {
                plugin.process_msg(&mut msg);
                if let Some(_new_payload_text) = msg.payload_text {
                    //println!("MuniicPlugin: msg: {}", new_payload_text);
                } else if msg.noar() == 13 {
                    //println!("MuniicPlugin: msg: {}", msg.payload_as_text().unwrap());
                }
                messages_processed += 1;
            }
            assert_eq!(messages_processed, 113160);

            let state = plugin.state();
            let state = state.read().unwrap();
            let state_value = &state.value;
            assert!(state_value.is_object());
            let state_obj = state_value.as_object().unwrap();
            assert!(state_obj.contains_key("name"));
            assert!(state_obj.contains_key("treeItems"));
            assert!(state_obj.contains_key("warnings"));

            let tree_items = state_obj.get("treeItems").unwrap();
            assert!(tree_items.is_array());
            let tree_items = tree_items.as_array().unwrap();
            // println!("tree_items: {:?}", tree_items);
            assert_eq!(tree_items.len(), 3); // warnings and regular items
                                             // check tree items:
            let non_null_tree_items = tree_items
                .iter()
                .filter(|ti| !ti.is_null())
                .collect::<Vec<&serde_json::Value>>();
            let item1: TreeItem = serde_json::from_value(non_null_tree_items[1].clone()).unwrap();
            assert_eq!(item1.label, "Interfaces #1, sorted by name");
        }
        Err(e) => {
            println!("MuniicPlugin::from_json failed with: {}", e);
        }
    }
}

pub fn muniic_full_example(c: &mut Criterion) {
    // initial version taking 76.5ms
    c.bench_function("muniic_full_example", |b| b.iter(parse_example_dlt));
}

criterion_group!(muniic_benches, muniic_full_example);
criterion_main!(muniic_benches);
