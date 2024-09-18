// The generated C code is not too important if we are going to write our own
// backend to go from koka mini to Clight but here it is 

/*
```
enum kk_eBPF_example__bpf__map__type_e {
  kk_eBPF_example_BPF__MAP__TYPE__ARRAY,
  kk_eBPF_example_BPF__MAP__TYPE__PERCPU__ARRAY,
  kk_eBPF_example_BPF__MAP__TYPE__HASH,
  kk_eBPF_example_BPF__MAP__TYPE__PERCPU__HASH
};
```
*/
type bpf_map_type
  BPF_MAP_TYPE_ARRAY
  BPF_MAP_TYPE_PERCPU_ARRAY
  BPF_MAP_TYPE_HASH
  BPF_MAP_TYPE_PERCPU_HASH

 
/*
Example of data type someone might want to store in an eBPF map
```
struct kk_eBPF_example_Vector3 {
  kk_integer_t x;
  kk_integer_t y;
  kk_integer_t z;
};
```
*/
value struct vector3
  x: int
  y: int
  z: int


/*
BTF style maps in C are annonymous structs which look like
```
struct {
    int (*type)[BPF_MAP_TYPE_ARRAY];
    int *key;
    struct v3 *value;
    int (*max_entries)[16];
} map SEC(.maps);
```
They use the dimensionality of the array to encode integer values for type and 
max_entries. Koka could take the legacy approach in terms of syntax but that is
undesirable because then you loose type information

https://ebpf-docs.dylanreimerink.nl/linux/concepts/maps/#btf-style-maps
*/

/*
BTF style maps in Koka
```
struct kk_eBPF_example_Map {
  kk_integer_t key;
  kk_eBPF_example__vector3 value;
  kk_integer_t max__entries;
  kk_eBPF_example__bpf__map__type type2;
};
```
*/

// Would be nice to have a macro like facility to simplify the map. In theory 
// could be one line:  `MAP(BPF_MAP_TYPE_ARRAY, vector3,      64)`
//                          ^                   ^             ^
//                          bpf_map_type        value type    max_entries

value struct map                  // can be any name
  type2: bpf_map_type             // Should be `type` but that's reserved by Alternatives
  key: int = 0                    // Nothing about this line should change
  value: vector3 = Vector3(0,0,0) // Can be any data type
  max_entries: int                // Nothing about this line should change

// Missing SEC(.maps) macro
val my_data = Map(type2 = BPF_MAP_TYPE_ARRAY, max_entries = 64)

fun main()
  println(my_data.key)
  println("Hello world!")
