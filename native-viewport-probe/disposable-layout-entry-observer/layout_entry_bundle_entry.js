// Compile this entry with frida-compile 16.4.1 and frida-java-bridge 7.0.13.
// Frida 17's bare Python create_script() does not supply a Java global.
import Java from 'frida-java-bridge';
import './layout_entry_observer.js';

// The observer module only accesses Java after an RPC call. Imports evaluate
// first, so this assignment is complete before the host can invoke arm().
globalThis.Java = Java;
