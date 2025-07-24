// External function declarations matching the Go exports
unsafe extern "C" {
    fn GetProof();
}

fn main() {
    unsafe {
        GetProof();
    }
}
