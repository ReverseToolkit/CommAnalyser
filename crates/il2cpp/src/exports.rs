//! Every `il2cpp_*` entry the bridge calls, resolved by name.
//!
//! A missing export stays null. Callers that need it return an error instead
//! of guessing a layout. Stripped builds can still fill [`Exports::override_export`].

use crate::ffi;
use crate::symbol::{self, find_export};
use runtime::module::Module;
use runtime::{Error, Result};
use std::collections::HashMap;

macro_rules! exports {
    ($($field:ident => $name:literal),+ $(,)?) => {
        #[derive(Clone, Debug)]
        pub struct Exports {
            $(pub $field: usize,)+
        }

        impl Exports {
            pub fn resolve(module: &Module, overrides: &HashMap<String, usize>) -> Result<Self> {
                Ok(Self {
                    $($field: lookup(module, overrides, $name)?,)+
                })
            }

            pub fn missing(&self) -> Vec<&'static str> {
                let mut names = Vec::new();
                $(
                    if self.$field == 0 {
                        names.push($name);
                    }
                )+
                names
            }
        }
    };
}

fn lookup(module: &Module, overrides: &HashMap<String, usize>, name: &str) -> Result<usize> {
    if let Some(address) = overrides.get(name) {
        return Ok(*address);
    }
    Ok(find_export(module, name)?.unwrap_or(0))
}

exports! {
    alloc => "il2cpp_alloc",
    array_length => "il2cpp_array_length",
    array_new => "il2cpp_array_new",
    assembly_get_image => "il2cpp_assembly_get_image",
    class_for_each => "il2cpp_class_for_each",
    class_from_name => "il2cpp_class_from_name",
    class_from_system_type => "il2cpp_class_from_system_type",
    array_class_get => "il2cpp_array_class_get",
    class_array_element_size => "il2cpp_class_array_element_size",
    class_get_assemblyname => "il2cpp_class_get_assemblyname",
    class_enum_basetype => "il2cpp_class_enum_basetype",
    class_get_declaring_type => "il2cpp_class_get_declaring_type",
    class_get_element_class => "il2cpp_class_get_element_class",
    class_get_field_from_name => "il2cpp_class_get_field_from_name",
    class_get_fields => "il2cpp_class_get_fields",
    class_get_flags => "il2cpp_class_get_flags",
    class_get_image => "il2cpp_class_get_image",
    class_instance_size => "il2cpp_class_instance_size",
    class_get_interfaces => "il2cpp_class_get_interfaces",
    class_get_method_from_name => "il2cpp_class_get_method_from_name",
    class_get_methods => "il2cpp_class_get_methods",
    class_get_name => "il2cpp_class_get_name",
    class_get_namespace => "il2cpp_class_get_namespace",
    class_get_nested_types => "il2cpp_class_get_nested_types",
    class_get_parent => "il2cpp_class_get_parent",
    class_get_static_field_data => "il2cpp_class_get_static_field_data",
    class_value_size => "il2cpp_class_value_size",
    class_get_type => "il2cpp_class_get_type",
    class_has_references => "il2cpp_class_has_references",
    runtime_class_init => "il2cpp_runtime_class_init",
    class_is_abstract => "il2cpp_class_is_abstract",
    class_is_assignable_from => "il2cpp_class_is_assignable_from",
    class_is_blittable => "il2cpp_class_is_blittable",
    class_is_enum => "il2cpp_class_is_enum",
    class_is_generic => "il2cpp_class_is_generic",
    class_is_inflated => "il2cpp_class_is_inflated",
    class_is_interface => "il2cpp_class_is_interface",
    class_is_subclass_of => "il2cpp_class_is_subclass_of",
    class_is_valuetype => "il2cpp_class_is_valuetype",
    domain_assembly_open => "il2cpp_domain_assembly_open",
    domain_get => "il2cpp_domain_get",
    domain_get_assemblies => "il2cpp_domain_get_assemblies",
    field_get_parent => "il2cpp_field_get_parent",
    field_get_flags => "il2cpp_field_get_flags",
    field_get_name => "il2cpp_field_get_name",
    field_get_offset => "il2cpp_field_get_offset",
    field_static_get_value => "il2cpp_field_static_get_value",
    field_get_type => "il2cpp_field_get_type",
    field_static_set_value => "il2cpp_field_static_set_value",
    free => "il2cpp_free",
    gc_collect => "il2cpp_gc_collect",
    gc_collect_a_little => "il2cpp_gc_collect_a_little",
    gc_disable => "il2cpp_gc_disable",
    gc_enable => "il2cpp_gc_enable",
    gc_foreach_heap => "il2cpp_gc_foreach_heap",
    gc_get_heap_size => "il2cpp_gc_get_heap_size",
    gc_get_max_time_slice_ns => "il2cpp_gc_get_max_time_slice_ns",
    gc_get_used_size => "il2cpp_gc_get_used_size",
    gchandle_get_target => "il2cpp_gchandle_get_target",
    gchandle_free => "il2cpp_gchandle_free",
    gchandle_new => "il2cpp_gchandle_new",
    gchandle_new_weakref => "il2cpp_gchandle_new_weakref",
    gc_is_disabled => "il2cpp_gc_is_disabled",
    gc_is_incremental => "il2cpp_gc_is_incremental",
    gc_set_max_time_slice_ns => "il2cpp_gc_set_max_time_slice_ns",
    gc_start_incremental_collection => "il2cpp_gc_start_incremental_collection",
    start_gc_world => "il2cpp_start_gc_world",
    stop_gc_world => "il2cpp_stop_gc_world",
    get_corlib => "il2cpp_get_corlib",
    image_get_assembly => "il2cpp_image_get_assembly",
    image_get_class => "il2cpp_image_get_class",
    image_get_class_count => "il2cpp_image_get_class_count",
    image_get_name => "il2cpp_image_get_name",
    initialize => "il2cpp_init",
    liveness_allocate => "il2cpp_unity_liveness_allocate_struct",
    liveness_begin => "il2cpp_unity_liveness_calculation_begin",
    liveness_end => "il2cpp_unity_liveness_calculation_end",
    liveness_from_statics => "il2cpp_unity_liveness_calculation_from_statics",
    liveness_finalize => "il2cpp_unity_liveness_finalize",
    liveness_free => "il2cpp_unity_liveness_free_struct",
    capture_memory_snapshot => "il2cpp_capture_memory_snapshot",
    free_captured_memory_snapshot => "il2cpp_free_captured_memory_snapshot",
    memory_snapshot_get_classes => "il2cpp_memory_snapshot_get_classes",
    memory_snapshot_get_objects => "il2cpp_memory_snapshot_get_objects",
    method_get_class => "il2cpp_method_get_class",
    method_get_flags => "il2cpp_method_get_flags",
    method_get_name => "il2cpp_method_get_name",
    method_get_object => "il2cpp_method_get_object",
    method_get_param_count => "il2cpp_method_get_param_count",
    method_get_param_name => "il2cpp_method_get_param_name",
    method_get_parameters => "il2cpp_method_get_parameters",
    method_get_param => "il2cpp_method_get_param",
    method_get_return_type => "il2cpp_method_get_return_type",
    method_is_generic => "il2cpp_method_is_generic",
    method_is_inflated => "il2cpp_method_is_inflated",
    method_is_instance => "il2cpp_method_is_instance",
    monitor_enter => "il2cpp_monitor_enter",
    monitor_exit => "il2cpp_monitor_exit",
    monitor_pulse => "il2cpp_monitor_pulse",
    monitor_pulse_all => "il2cpp_monitor_pulse_all",
    monitor_try_enter => "il2cpp_monitor_try_enter",
    monitor_try_wait => "il2cpp_monitor_try_wait",
    monitor_wait => "il2cpp_monitor_wait",
    object_get_class => "il2cpp_object_get_class",
    object_get_virtual_method => "il2cpp_object_get_virtual_method",
    object_init => "il2cpp_runtime_object_init_exception",
    object_new => "il2cpp_object_new",
    object_get_size => "il2cpp_object_get_size",
    object_unbox => "il2cpp_object_unbox",
    resolve_icall => "il2cpp_resolve_icall",
    string_chars => "il2cpp_string_chars",
    string_length => "il2cpp_string_length",
    string_new => "il2cpp_string_new",
    value_box => "il2cpp_value_box",
    thread_attach => "il2cpp_thread_attach",
    thread_detach => "il2cpp_thread_detach",
    thread_get_all_attached => "il2cpp_thread_get_all_attached_threads",
    thread_current => "il2cpp_thread_current",
    is_vm_thread => "il2cpp_is_vm_thread",
    type_equals => "il2cpp_type_equals",
    class_from_type => "il2cpp_class_from_type",
    type_get_name => "il2cpp_type_get_name",
    type_get_object => "il2cpp_type_get_object",
    type_get_type => "il2cpp_type_get_type",
}

impl Exports {
    pub fn call(&self, slot: usize, args: &[u64]) -> Result<u64> {
        if slot == 0 {
            return Err(Error::NotFound("il2cpp export".into()));
        }
        ffi::call_ptr(slot, args)
    }

    pub fn required(&self, slot: usize, name: &str) -> Result<usize> {
        if slot == 0 {
            Err(Error::NotFound(name.into()))
        } else {
            Ok(slot)
        }
    }
}

pub fn load(overrides: &HashMap<String, usize>) -> Result<(runtime::module::Module, Exports)> {
    let module = symbol::find_module()?;
    let exports = Exports::resolve(&module, overrides)?;
    if exports.domain_get == 0 || exports.get_corlib == 0 {
        return Err(Error::NotFound(
            "il2cpp_domain_get/il2cpp_get_corlib are not exported".into(),
        ));
    }
    Ok((module, exports))
}
