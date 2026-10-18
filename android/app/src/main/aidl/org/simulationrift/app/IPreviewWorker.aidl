package org.simulationrift.app;

import android.os.SharedMemory;

// The isolated worker for previews and scans (§8.6). Requests and replies are rift-protocol
// frames; the controller validates every reply against its request. Input is
// a sealed, read-only memfd; output pixels go into the controller's region.
interface IPreviewWorker {
    // Answers a Hello frame with the worker's own account of its confinement.
    byte[] hello(in byte[] request);
    // Decodes or renders `input` into `output` (RGBA8, unpremultiplied).
    byte[] render(in byte[] request, in ParcelFileDescriptor input, in SharedMemory output);
    // Runs a request whose only output is its reply frame (LoadRules, Scan).
    byte[] call(in byte[] request, in ParcelFileDescriptor input);
}
