package dev.busung.s25uroot

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Activity-scoped investigation evidence and long-running local extraction.
 * Source URI grants are held only in memory, never serialized or uploaded.
 */
internal class InvestigationSession : ViewModel() {
    val report = mutableStateOf<InvestigationReport?>(null)
    val imported = mutableStateOf<List<FirmwareInspection>>(emptyList())
    val selectedSources = mutableStateOf<Map<String, Uri>>(emptyMap())
    val pendingBootSource = mutableStateOf<Uri?>(null)
    val kernelConfig = mutableStateOf<KernelConfigCapture?>(null)
    val status = mutableStateOf("Not yet collected")

    val extracting = mutableStateOf(false)
    val extractionStatus = mutableStateOf("")
    val extractionResult = mutableStateOf<BootExtractionResult?>(null)
    private var extractionJob: Job? = null

    fun cancelBootExtraction() {
        extractionJob?.cancel()
    }

    fun extractBoot(context: Context, source: Uri, sourceName: String, destination: Uri) {
        if (extractionJob?.isActive == true) return
        val appContext = context.applicationContext
        extracting.value = true
        extractionResult.value = null
        extractionStatus.value = "Opening firmware package"
        extractionJob = viewModelScope.launch {
            var completed = false
            var partialDeleted = false
            try {
                val result = withContext(Dispatchers.IO) {
                    val jobContext = currentCoroutineContext()
                    val resolver = appContext.contentResolver
                    val inStream = resolver.openInputStream(source)
                        ?: error("Cannot open selected firmware package")
                    inStream.use { firmware ->
                        val outStream = resolver.openOutputStream(destination, "w")
                            ?: error("Cannot open destination for boot.img.lz4")
                        outStream.use { out ->
                            BootImageExtractor.extract(
                                source = firmware,
                                sourceName = sourceName,
                                output = out,
                                checkCancelled = { jobContext.ensureActive() },
                                progress = { bytes ->
                                    extractionStatus.value =
                                        "Scanning AP: " + (bytes / (1024L * 1024L)) + " MiB consumed"
                                },
                            )
                        }
                    }
                }
                extractionResult.value = result
                extractionStatus.value = "Saved boot.img.lz4 (" + result.sizeBytes +
                    " bytes); SHA-256 computed"
                completed = true
            } catch (_: CancellationException) {
                extractionStatus.value = "Extraction cancelled"
            } catch (error: Exception) {
                extractionStatus.value = "Extraction failed: " +
                    (error.message ?: error.javaClass.simpleName)
            } finally {
                if (!completed) {
                    // Best effort remove a partially written document. SAF providers
                    // may decline deletion; disclose that case rather than leaving
                    // a partial image silently labeled as valid.
                    partialDeleted = withContext(Dispatchers.IO) {
                        runCatching {
                            DocumentsContract.deleteDocument(appContext.contentResolver, destination)
                        }.getOrDefault(false)
                    }
                    if (!partialDeleted) {
                        extractionStatus.value +=
                            " — remove the incomplete destination document manually"
                    }
                }
                extracting.value = false
            }
        }
    }
}
