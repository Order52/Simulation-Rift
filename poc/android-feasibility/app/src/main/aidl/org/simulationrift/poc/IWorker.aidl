package org.simulationrift.poc;

// Control contract between the controller and the isolated worker.
// Inputs are descriptors only; outputs are bounded strings or a caller-owned
// SharedMemory region carried in the Bundle.
interface IWorker {
    String probe(String canaryPath, int tcpPort);
    String renderPdf(in ParcelFileDescriptor pdf, int pageIndex, in Bundle output);
    String yaraScan(String rules, in ParcelFileDescriptor input);
}
