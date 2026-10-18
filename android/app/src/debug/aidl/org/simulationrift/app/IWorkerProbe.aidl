package org.simulationrift.app;

// Debug builds only: asks a worker-identical isolated process what it can
// reach (S3, S4). Returns key=value lines.
interface IWorkerProbe {
    String probe(String canaryPath, int tcpPort);
}
