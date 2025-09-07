package com.example.virusscan.domain.usecase

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.DeadObjectException
import android.os.TransactionTooLargeException
import android.provider.MediaStore
import com.det.common.R
import com.example.virusscan.components.AntiVirusScanState
import com.example.virusscan.components.ScanStatus
import com.example.virusscan.components.VirusStatus
import com.example.virusscan.core.utils.DispatureProvider
import com.example.virusscan.core.utils.MalwareScannerHelper
import com.example.virusscan.core.utils.MyLocalData
import com.example.virusscan.core.utils.MyLocalData.formatDuration
import com.example.virusscan.core.utils.deleteFile
import com.example.virusscan.core.utils.hasManagePermissions
import com.example.virusscan.core.utils.isDeviceLockEnabled
import com.example.virusscan.core.utils.isTrue
import com.example.virusscan.core.utils.isUsbDebuggingEnabled
import com.example.virusscan.core.utils.safeLength
import com.example.virusscan.core.utils.setLog
import com.example.virusscan.core.utils.toMalwareModel
import com.example.virusscan.data.MyPref
import com.example.virusscan.domain.components.IssuesType
import com.example.virusscan.domain.model.AppModel
import com.example.virusscan.domain.model.IssueModel
import com.example.virusscan.domain.model.MalwareModel
import com.example.virusscan.domain.model.VulnerabilitiesModel
import com.example.virusscan.domain.model.VulnerabilitiesType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Collections
import kotlin.math.min

class VirusScanUsecase(
    private val context: Context,
    private val malwareScanner: MalwareScannerHelper,
    private val loadAllFilesUseCase: LoadAllFilesUseCase,
    private val loadAppsUseCase: GetInstalledAppsUseCase,
    private val dispatureProvider: DispatureProvider,
    private val pref: MyPref
) {
    private val _scanState = MutableStateFlow(AntiVirusScanState())
    val scanState = _scanState.asStateFlow()
    private val visitedFiles = mutableListOf<String>()

    suspend operator fun invoke() {
        scanningProcessFull()
    }

    private val maliciousPackages = listOf(
        "uk.co.extorian.EICARAntiVirusTest",
        "com.montimage.eicar_virus",
        "com.androidantivirus.testvirus",
        "com.ikarus.ikarustestvirus"
    )

    suspend fun deleteMalwareFiles(isDelete: Boolean) {
        val malwareList = scanState.value.malwareList
        if (malwareList.isEmpty()) {
            return
        }
        for (malwareModel in malwareList) {
            deleteMalware(malwareModel, isDelete)
        }
    }

    suspend fun ignoreMalware(malwareModel: MalwareModel) {
        val malwareList = scanState.value.malwareList.toMutableList()
        if (malwareList.isEmpty()) {
            return
        }
        val index = malwareList.indexOfFirst { it.name.contains(malwareModel.name) }
        if (index != -1) {
            malwareList.removeAt(index)
        }
        _scanState.update {
            it.copy(malwareList = malwareList)
        }
    }

    suspend fun ignoreApp(app: AppModel) {
        val appList = scanState.value.appList.toMutableList()
        if (appList.isEmpty()) {
            return
        }
        val index = appList.indexOfFirst { it.pkgName == app.pkgName }
        if (index != -1) {
            appList.removeAt(index)
        }
        _scanState.update {
            it.copy(appList = appList)
        }
    }

    fun resetVirusState() {
        _scanState.update {
            it.copy(
                isStopClick = true
            )
        }
        _scanState.update {
            AntiVirusScanState()
        }
    }

    suspend fun removeApp(appPkg: String) {
        val appList = scanState.value.appList.toMutableList()
        if (appList.isEmpty()) {
            return
        }
        val index = appList.indexOfFirst { it.pkgName == appPkg }
        if (index != -1) {
            appList.removeAt(index)
        }
        _scanState.update {
            it.copy(appList = appList)
        }
        checkIssueAndUpdateStatus(false)
    }

    suspend fun deleteMalware(
        malwareModel: MalwareModel, isDelete: Boolean, fromDeep: Boolean = false
    ) {
        withContext(dispatureProvider.io) {
            if (isDelete) {
                val fileToDelete = File(malwareModel.path)
                if (fileToDelete.exists()) {
                    deleteFile(context, fileToDelete)
                }
            } else {
                ignoreIssue(malwareModel.name, IssuesType.Malware)
            }
            val list = scanState.value.malwareList.toMutableList()
            val index = list.indexOfFirst { it.name.contains(malwareModel.name) }
            if (index != -1) {
                list.removeAt(index)
            }
            _scanState.update {
                it.copy(
                    malwareList = list, operatedIssue = scanState.value.operatedIssue + 1
                )
            }
            checkIssueAndUpdateStatus(fromDeep)
        }
    }

    fun allIssuesSolved() {
        _scanState.update {
            it.copy(
                virusStatus = VirusStatus.Protected
            )
        }
    }

    fun someIssuesLeft() {
        _scanState.update {
            it.copy(
                virusStatus = VirusStatus.ResolveIssues
            )
        }
    }

    fun checkIssueAndUpdateStatus(fromDeep: Boolean) {
        setLog("scanVirus", "checkIssueAndUpdateStatus")
        if (_scanState.value.totalThreat() == 0) {
            setLog("scanVirus", "threat o")
            if (fromDeep) {
                resetState()
            } else {
                processCompleteScan()
            }
        }
    }

    suspend fun ignoreIssue(key: String, issuesType: IssuesType, isFromDeep: Boolean = false) {
        withContext(dispatureProvider.io) {
            when (issuesType) {
                IssuesType.Malware -> pref.ignoreMalwareList = pref.ignoreMalwareList + ";" + key
                IssuesType.Valnerabilties -> pref.ignoreVulnabilitiesList =
                    pref.ignoreVulnabilitiesList + ";" + key

                IssuesType.Permission -> pref.ignoreAppList = pref.ignoreAppList + ";" + key
                IssuesType.App -> pref.ignoreAppList = pref.ignoreAppList + ";" + key
            }
            checkIssueAndUpdateStatus(isFromDeep)
        }
    }

    suspend fun checkIssueIsIgnore(key: String, issuesType: IssuesType): Boolean {
        return withContext(dispatureProvider.io) {
            when (issuesType) {
                IssuesType.Malware -> pref.ignoreMalwareList.split(";")
                    .indexOfFirst { it == key } != -1

                IssuesType.Valnerabilties -> pref.ignoreVulnabilitiesList.split(";")
                    .indexOfFirst { it == key } != -1

                IssuesType.Permission -> pref.ignoreAppList.split(";")
                    .indexOfFirst { it == key } != -1

                IssuesType.App -> pref.ignoreAppList.split(";").indexOfFirst { it == key } != -1
            }
        }
    }

    suspend fun stopClick(isStop: Boolean = true) {
        withContext(dispatureProvider.io) {
            if (isStop) {
                _scanState.update {
                    it.copy(
                        isStopClick = true
                    )
                }
            } else {
                resetState()
            }
        }
    }

    fun showThreatsResult(
    ) {
        statusUpdateScanner(
            ScanStatus.ThreatsResult,
        )
    }

    fun processCompleteScan(
    ) {
        visitedFiles.clear()
        statusUpdateScanner(ScanStatus.VirusFinished)
    }

    private fun statusUpdateScanner(
        virusVerifiedStatus: ScanStatus
    ) {
        return _scanState.update { it.copy(scanStatus = virusVerifiedStatus) }
    }

    /*private suspend fun addMalware(malwareModel: List<MalwareModel>) {
        setLog("Files_Scan", "To In add: $malwareModel")
        val list = scanState.value.malwareList.toMutableList()
        setLog("Files_Scan", "In add previous List: $list")
        malwareModel.forEach { malware ->
            if (checkIssueIsIgnore(malware.name, IssuesType.Malware)) {
                return
            } else {
                list.addAll(malwareModel)
                setLog("Files_Scan", "In add new List: $list")
//                setMalwareList(list.distinctBy { it.path.trim().lowercase() })
                setMalwareList(list)
            }
        }
    }*/

    private suspend fun addMalware(malwareModel: List<MalwareModel>) {
        setLog("Files_Scan", "To In add: $malwareModel")

        _scanState.update { state ->
            val current = state.malwareList.toMutableList()

            // Only add non-ignored items
            val newOnes = malwareModel.filterNot { checkIssueIsIgnore(it.name, IssuesType.Malware) }

            val updated = current.apply { addAll(newOnes) }
                .distinctBy { it.path.trim().lowercase() }

            setLog("Files_Scan", "In set: $updated")

            state.copy(malwareList = updated)
        }
    }


    private suspend fun addAppList(appModel: List<AppModel>) {
        val list = scanState.value.appList.toMutableList()
        appModel.forEach { app ->
            if (checkIssueIsIgnore(app.pkgName, IssuesType.App)) {
                return
            } else {
                list.addAll(appModel)
                setAppList(list.distinctBy { it.pkgName.trim().lowercase() })
            }
        }
    }

    private suspend fun addVulnerabilities(): List<VulnerabilitiesModel> {
        val vulnerabilitiesList = arrayListOf<VulnerabilitiesModel>()
        val usbDebugEnabled = context.isUsbDebuggingEnabled()
        val lockScreenEnabled = context.isDeviceLockEnabled()
        if (usbDebugEnabled && !checkIssueIsIgnore(
                VulnerabilitiesType.USB_DEBUG.name, IssuesType.Valnerabilties
            )
        ) {
            vulnerabilitiesList.add(
                VulnerabilitiesModel(
                    VulnerabilitiesType.USB_DEBUG,
                    title = context.getString(R.string.developer_option_is_on),
                    message = context.getString(R.string.turn_off_developer_options),
                    icon = R.drawable.ic_app_lock
                )
            )
        }
        if (!lockScreenEnabled && !checkIssueIsIgnore(
                VulnerabilitiesType.LOCK_SCREEN.name, IssuesType.Valnerabilties
            )
        ) {
            vulnerabilitiesList.add(
                VulnerabilitiesModel(
                    VulnerabilitiesType.LOCK_SCREEN,
                    title = context.getString(R.string.lock_screen_disabled),
                    message = context.getString(R.string.lock_screen_disabled_desc),
                    icon = R.drawable.ic_app_lock
                )
            )
        }
        return vulnerabilitiesList
    }

    suspend fun updateValnabilities(
        type: VulnerabilitiesType, isIgnore: Boolean = false, fromDeep: Boolean = false
    ) {
        withContext(dispatureProvider.io) {
            val vList = scanState.value.valneList.toMutableList()
            if (isIgnore) {
                ignoreIssue(type.name, IssuesType.Valnerabilties)
                val index = vList.indexOfFirst { it.type == type }
                if (index != -1) {
                    vList.removeAt(index)
                }
                _scanState.update {
                    it.copy(valneList = vList, operatedIssue = scanState.value.operatedIssue + 1)
                }
            } else {
                setLog("scanVirus", "$fromDeep")
                if (type.isTrue(context)) {
                    setLog("scanVirus", "No change")
                    _scanState.update {
                        it.copy(valneList = vList)
                    }
                } else {
                    setLog("scanVirus", "Off")
                    val index = vList.indexOfFirst { it.type == type }
                    if (index != -1) {
                        vList.removeAt(index)
                    }
                    _scanState.update {
                        it.copy(
                            valneList = vList, operatedIssue = scanState.value.operatedIssue + 1
                        )
                    }
                }
            }
            checkIssueAndUpdateStatus(fromDeep)
        }
    }

    private fun setMalwareList(list: List<MalwareModel>) {
        setLog("Files_Scan", "In set: $list")
        _scanState.update {
            it.copy(
                malwareList = list
            )
        }
    }

    private fun setAppList(list: List<AppModel>) {
        _scanState.update {
            it.copy(
                appList = list
            )
        }
    }

    private fun setIssueList(list: List<IssueModel>) {
        _scanState.update {
            it.copy(issuesList = list)
        }
    }

    private fun addIssue(issueModel: IssueModel) {
        val list = scanState.value.issuesList.toMutableList()
        list.add(issueModel)
        setIssueList(list)
    }

    private suspend fun afterSuccessProgressFull(
        allApps: List<AppModel>, allFolders: List<File>
    ) {
        malwareScanner.scannedApps = 0
        malwareScanner.scannedFiles = 0
        _scanState.update {
            it.copy(
                filesSize = 0,
                apksSize = 0,
                totalApps = allApps.size,
                totalFiles = allFolders.size,
                totalApksCount = allApps.size,
                estimateScanTime = getEstimatedTimeText((allApps.size + allFolders.size)),
                scanStatus = ScanStatus.PreVirusScanning,
            )
        }
        withContext(dispatureProvider.io) {
            // Run both app scanning and file scanning concurrently
            val fileScanJob = async {
                loopOnFiles(allFolders) // Your file scanning logic
                setLog("Files_Scan", "File scan completed")
            }
            val appScanJob = async {
                allApps.forEachIndexed { index, app ->

                    val progress = ((index + 1).toFloat() / allApps.size.toFloat()) * 100f

                    val virusApp =
                        if (malwareScanner.scanFile(File(app.directory))?.isNotEmpty() == true) {
                            app
                        } else if (maliciousPackages.contains(app.pkgName)) {
                            app
                        } else {
                            null
                        }

                    // Add detected malware
                    if (virusApp != null) {
                        addAppList(listOf(virusApp))
                    }

                    delay(150)
                    setLog("Virus_Scanning", "App Scanned: ${app.pkgName}")
                    // Update scan progress for apps
                    if (!scanState.value.isStopClick) {
                        withContext(Dispatchers.Main) {
                            _scanState.update {
                                it.copy(
                                    appModel = app,
                                    scannedApps = index + 1, // Correct scanned count
                                    apkProgress = progress.toInt(),
                                    maxApk = allApps.size
                                )
                            }
                        }
                    }
                }
                setLog("cvv", "App scan completed")
            }

            // Wait for both jobs to complete
            fileScanJob.await()
            appScanJob.await()


            if (!scanState.value.isStopClick) {
                _scanState.update {
                    it.copy(
                        totalInfectedFiles = scanState.value.malwareList.size,
                        totalApps = allApps.size,
                        totalFiles = allFolders.size,
                        fileProgress = 0
                    )
                }
                startWeightedProgressScanWithState(
                    scanState.value.totalThreat(),
                    allApps,
                    allFolders
                )
            }
        }
    }

    fun getEstimatedTimeText(totalFiles: Int): String {

        setLog("Virus_Scan", "Total files: $totalFiles")

        val avgMillisPerFile = 66 // adjust if needed
        val totalMillis = (totalFiles * avgMillisPerFile).toLong()

        val totalSeconds = totalMillis / 1000
        val minutes = totalSeconds / 60
        val seconds = totalSeconds % 60

        return "Est. scanning time: ${minutes}m ${seconds}s"
    }


    suspend fun startWeightedProgressScanWithState(
        infectedFiles: Int, apps: List<AppModel>, files: List<File>
    ) {

        val filePaths = files.map { it.path }
        val appPackages = apps.map { it.pkgName }
        val allPaths: List<String> = filePaths + appPackages

        for (i in 1..100) {

            val pgInjectedFiles = (infectedFiles * i) / 100
            val pgScannedFiles = (files.size * i) / 100
            val pgScannedApps = (apps.size * i) / 100
            val pathIndex = min(((allPaths.size * i) / 100), allPaths.lastIndex)
            setLog("loopOnFiles", "Current Path Index: $pathIndex")
            val currentPath = allPaths[pathIndex]

            _scanState.update {
                it.copy(
                    infectedFiles = pgInjectedFiles,
                    scannedApps = pgScannedApps,
                    scannedFiles = pgScannedFiles,
                    fileProgress = i,
                    filePath = currentPath,
                    scanStatus = ScanStatus.VirusScanning
                )
            }

            delay(100)
        }

        delay(500)

        if (!scanState.value.isStopClick) {
            // Update total time and status after both scans are done
            val whenEnds = System.currentTimeMillis()
            val timeTakenMillis = whenEnds - scanState.value.whenStarted
            val timeTaken = formatDuration(timeTakenMillis)

            // Final update
            _scanState.update {
                it.copy(
                    scannedApps = apps.size,
                    scannedFiles = files.size,
                    fileProgress = 0,
                    totalTimee = timeTakenMillis,
                    timeInStr = timeTaken,
                    filePath = "",
                    scanStatus = ScanStatus.ScanCompleted,
                )
            }
        }
    }

    private suspend fun loopOnFiles(allFolders: List<File>) {
        setLog("Files_Scan", "Loop on files called!")

        val visitedFiles = Collections.synchronizedSet(mutableSetOf<String>())
        val stack = ArrayDeque<List<File>>()
        stack.addLast(allFolders)

        val semaphore = Semaphore(4) // limit to 4 concurrent scans
        val scope = CoroutineScope(Dispatchers.IO)

//        var stackCounts = 0
//        var filesCounts = 0
//        var emptyFolders = 0
//        var fileFolders = 0
        var scannedFiles = 0

        while (stack.isNotEmpty()) {
//            stackCounts++
            val currentFolder = stack.removeLast()

            val scanJobs = currentFolder.mapNotNull { file ->
                if (visitedFiles.contains(file.absolutePath)) {
                    return@mapNotNull null
                }

//                filesCounts++
                visitedFiles.add(file.absolutePath)

                scope.async {
                    semaphore.acquire()
                    try {
                        if (scanState.value.isStopClick) return@async

                        if (file.isDirectory) {
                            val subFiles = file.listFiles()?.toList() ?: emptyList()
                            if (subFiles.isNotEmpty()) {
                                synchronized(stack) {
//                                    fileFolders++
                                    stack.addLast(subFiles)
                                }
                            } else {
//                                emptyFolders++
                            }
                        } else {
                            try {
                                scannedFiles++
                                val virusList = malwareScanner.scanFile(file)
                                if (!virusList.isNullOrEmpty()) {
                                    val malware = virusList.mapNotNull { appInfo ->
                                        setLog("Files_Scan", "Malware Found Path: ${appInfo.toMalwareModel()?.path}")
                                        appInfo.toMalwareModel()
                                    }
                                    setLog("Files_Scan", "Malware Found: ${malware.size}")
                                    addMalware(malware)
                                }
                            } catch (e: Exception) {
                                setLog("Files_Scan", "Error Scanning File: ${e.message}")
                            }

                            if (scannedFiles == 1 || scannedFiles % 50 == 0) {
                                withContext(Dispatchers.Main) {
                                    _scanState.update {
                                        it.copy(
                                            scannedCount = it.scannedCount + 1,
                                            filePath = file.path
                                        )
                                    }
                                }
                            }
//                            setLog("Files_Scan", "File Scanned: ${file.path}")
                        }
                    } finally {
                        semaphore.release()
                    }
                }
            }

            scanJobs.awaitAll()
        }

//        setLog("Files_Scan", "Stack Count: $stackCounts")
//        setLog("Files_Scan", "Files Counts: $filesCounts")
//        setLog("Files_Scan", "Empty Folders: $emptyFolders")
//        setLog("Files_Scan", "File Folders: $fileFolders")
        setLog("Files_Scan", "Scanned Files: $scannedFiles")
        setLog("Files_Scan", "Scan Completed")
    }


    fun countAllFiles2(folders: List<File>): Int {
        return folders.filter { it.isDirectory }.sumOf { folder ->
            folder.walk().filter { it.isFile }.count()
        }
    }

    private suspend fun countAllFiles(folders: List<File>): Int {
        setLog("Files_Scan", "Count All Files called!")
        return withContext(dispatureProvider.io) {
            var totalFileCount = 0
            val stack = mutableListOf<List<File>>() // Your original stack type
            val visitedPaths = mutableSetOf<String>()

            stack.add(folders)

            while (stack.isNotEmpty()) {
                val currentFiles = stack.removeAt(stack.lastIndex)

                // Split into chunks of max 4 files for concurrency
                val chunks = currentFiles.chunked(4)

                chunks.map { chunk ->
                    async {
                        val localNewStacks = mutableListOf<List<File>>()
                        var localCount = 0

                        for (file in chunk) {
                            val absolutePath = file.absolutePath
                            if (!visitedPaths.add(absolutePath)) {
                                continue
                            }

                            localCount++

                            if (file.isDirectory) {
                                val subFiles = file.listFiles()?.toList() ?: emptyList()
                                if (subFiles.isNotEmpty()) {
                                    localNewStacks.add(subFiles)
                                }
                            }
                        }
                        Pair(localCount, localNewStacks)
                    }
                }.awaitAll().forEach { (count, newStacks) ->
                    totalFileCount += count
                    stack.addAll(newStacks)
                }
            }
            totalFileCount
        }
    }


    fun resetState() {
        setLog("Antivirus_Log", "resetState: called!")
        visitedFiles.clear()
        _scanState.update {
            AntiVirusScanState()
        }
    }

    private suspend fun scanningProcessFull() {
        withContext(dispatureProvider.io) {
            try {
                resetState()
                visitedFiles.clear()
                if (!hasManagePermissions(context)) {
                    _scanState.update {
                        it.copy(
                            isPermission = false, scanStatus = ScanStatus.VirusScanning
                        )
                    }
                } else {
                    setLog("Antivirus_Log", "scanningProcess: started")
                    _scanState.update {
                        it.copy(
                            whenStarted = System.currentTimeMillis(),
                            scanStatus = ScanStatus.FilesFetching,
                            filePath = "Initiating...",
                            fileProgress = 0
                        )
                    }
                    setLog("cvv", "scanningProcess: Started ")
                    val allFolders = loadAllFiles(context)
                    val appList = getApps(context)
                    setLog("cvv", "All File Size ${allFolders.size} ")
                    setLog("cvv", "All Apps Size ${appList.size} ")

                    afterSuccessProgressFull(appList, allFolders)

                }
            } catch (_: Exception) {
            } catch (_: ArrayIndexOutOfBoundsException) {
            } catch (_: OutOfMemoryError) {
            }
        }
    }

    private suspend fun loadAllFiles(
        context: Context
    ): List<File> {
        setLog(
            "Fetch_Check",
            "Load All Files Called!"
        )
        return withContext(dispatureProvider.io) {
            val allFilesList = mutableListOf<File>()
            try {
                // Get the content URI for files, depending on the Android version
                val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val volumeNames = MediaStore.getExternalVolumeNames(context)
                    if (volumeNames.isNotEmpty()) {
                        val item = volumeNames.firstOrNull()
                        if (item != null) {
                            MediaStore.Files.getContentUri(item)
                        } else {
                            MediaStore.Files.getContentUri("external")
                        }
                    } else {
                        MediaStore.Files.getContentUri("external")
                    }
                } else {
                    MediaStore.Files.getContentUri("external")
                }
                // Ensure the app has the required permission to access all files
                if (hasManagePermissions(context)) {
                    // Define projection for the query
                    val projection = arrayOf(
                        MediaStore.Files.FileColumns._ID,
                        MediaStore.Files.FileColumns.DISPLAY_NAME,
                        MediaStore.Files.FileColumns.DATA,
                        MediaStore.Files.FileColumns.SIZE
                    )

                    // Query for all files
                    val cursor = context.contentResolver.query(
                        uri, projection, null, null, null
                    )

                    cursor?.use { cur ->
                        if (cur.count > 0) {
                            cur.moveToFirst()
                            while (!cur.isAfterLast) {
                                try {
                                    val path =
                                        cur.getString(cur.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DATA))
                                    allFilesList.add(File(path))
                                    if (allFilesList.size == 1 || allFilesList.size % 50 == 0) {
                                        _scanState.update {
                                            it.copy(
                                                whenStarted = System.currentTimeMillis(),
                                                scanStatus = ScanStatus.FilesFetching,
                                                filePath = path
                                            )
                                        }
                                    }
                                } catch (e: Exception) {
                                    e.printStackTrace()
                                }
                                cur.moveToNext()
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
            allFilesList
        }
    }

    private suspend fun getApps(
        context: Context,
        allowSystemApps: Boolean = false,
    ): List<AppModel> {
        setLog(
            "Fetch_Check",
            "Load Apps Called!"
        )
        return withContext(dispatureProvider.io) {
            val tempApps = mutableListOf<AppModel>()
            try {
                val appsList = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    context.packageManager.getInstalledApplications(
                        PackageManager.ApplicationInfoFlags.of(
                            PackageManager.GET_META_DATA.toLong()
                        )
                    )
                } else {
                    context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                }

                for (item in appsList) {
                    try {
                        val appName = MyLocalData.getAppNameFromPkgName(context, item.packageName)
                        val appIcon = MyLocalData.getAppIcon(context, item.packageName)
                        val appPermissions =
                            MyLocalData.getAppPermissions(context, item.packageName)
                        val appFile = File(item.publicSourceDir)
                        val installedTime: Long = appFile.lastModified()
                        val appSize: Long = appFile.safeLength()
                        val sizeInMb = MyLocalData.sizeIntoMb(context, appSize)
                        if (appName != null && appIcon != null) {
                            val model = AppModel(
                                appName,
                                item.packageName,
                                appIcon,
                                item.publicSourceDir,
                                MyLocalData.appInstalledOrNot(context, item.packageName),
                                appPermissions,
                                installedTime,
                                appSize,
                                sizeInMb.toString()
                            )
                            if (item.packageName != context.packageName) {
                                if (allowSystemApps) {
                                    tempApps.add(model)
                                    _scanState.update {
                                        it.copy(
                                            whenStarted = System.currentTimeMillis(),
                                            scanStatus = ScanStatus.FilesFetching,
                                            filePath = model.pkgName
                                        )
                                    }
                                } else {
                                    if ((item.flags and (ApplicationInfo.FLAG_UPDATED_SYSTEM_APP or ApplicationInfo.FLAG_SYSTEM) <= 0)) {
                                        tempApps.add(model)
                                        _scanState.update {
                                            it.copy(
                                                whenStarted = System.currentTimeMillis(),
                                                scanStatus = ScanStatus.FilesFetching,
                                                filePath = model.pkgName
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    } catch (_: TransactionTooLargeException) {
                    } catch (_: PackageManager.NameNotFoundException) {
                    } catch (_: DeadObjectException) {
                    } catch (_: Exception) {
                    }
                }
            } catch (_: TransactionTooLargeException) {
            } catch (_: PackageManager.NameNotFoundException) {
            } catch (_: DeadObjectException) {
            } catch (_: Exception) {
            }
            tempApps
        }
    }


}