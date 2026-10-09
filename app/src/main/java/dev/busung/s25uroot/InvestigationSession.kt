package dev.busung.s25uroot

import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel

/**
 * Activity-scoped session survives switching away from the Investigate tab.
 * Evidence remains local and in memory until explicitly exported. No persistence
 * of firmware identifiers or root-related observations without user consent.
 */
internal class InvestigationSession : ViewModel() {
    val report = mutableStateOf<InvestigationReport?>(null)
    val imported = mutableStateOf<FirmwareInspection?>(null)
    val kernelConfig = mutableStateOf<KernelConfigCapture?>(null)
    val status = mutableStateOf("Not yet collected")
}
