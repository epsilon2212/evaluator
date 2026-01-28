Provides a synchronized communication between two groups of processes with certain limitations (e.g number of processes from the same group running concurrently).
Demonstrates usage of pipes, forks, execs, signals and general synchronization.

There are two groups of processes: policies and environments.
Environment, in order to mutate, needs an idle policy process (whichever).
Environment finishes when produces a terminal state.
One test is being handled by exactly one environment.
The maximum number of environments or policies working concurrently is passed in *argv[].
