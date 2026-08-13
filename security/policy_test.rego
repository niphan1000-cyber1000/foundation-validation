package main

# Force OPA test assertion to fail
test_deliberate_failure {
    false == true
}
