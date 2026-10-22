// The Android libraries in this APK and the licences their POMs declare
// (§25), written to build/generated-notices/android/notices/
// android-libraries.txt for the module's assets. Rift uses every library
// under the Apache License 2.0, whose text the APK carries, or else under
// the MIT License, whose text (with the copyright line) is then kept here;
// the build fails for any other library. Texts a library's own archive
// does not carry (JNA's, libffi's, which its native code links, and the
// MIT ones) are kept in licence-texts/android/<artifact>-<version>/ and
// appended.
import javax.xml.parsers.DocumentBuilderFactory
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.maven.MavenModule
import org.gradle.maven.MavenPomArtifact
import org.w3c.dom.Element

val noticesDir = layout.buildDirectory.dir("generated-notices/android")
val keptTexts = rootProject.file("licence-texts/android")
// The release runtime classpath's modules (the graph only: no artifacts, so
// no variant selection). The configuration is created by the Android plugin
// after this script runs, so it is looked up lazily.
val modules = provider {
    configurations.getByName("releaseRuntimeClasspath").incoming.resolutionResult.allComponents
        .mapNotNull { it.id as? ModuleComponentIdentifier }
        .map { "${it.group}:${it.module}:${it.version}" }.sorted()
}

/** The licences a POM declares, and its parent's coordinates. */
fun readPom(file: File): Pair<List<String>, String?> {
    val factory = DocumentBuilderFactory.newInstance().apply {
        isExpandEntityReferences = false
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    }
    val root = factory.newDocumentBuilder().parse(file).documentElement
    fun Element.child(name: String) = (0 until childNodes.length).map { childNodes.item(it) }
        .filterIsInstance<Element>().filter { it.tagName == name }
    val licences = root.child("licenses").flatMap { it.child("license") }
        .mapNotNull { it.child("name").firstOrNull()?.textContent?.trim() }
    val parent = root.child("parent").firstOrNull()?.let { p ->
        listOf("groupId", "artifactId", "version").map { p.child(it).single().textContent.trim() }.joinToString(":")
    }
    return licences to parent
}

fun pomOf(group: String, name: String, version: String): File? =
    dependencies.createArtifactResolutionQuery().forModule(group, name, version)
        .withArtifacts(MavenModule::class.java, MavenPomArtifact::class.java).execute()
        .resolvedComponents.flatMap { it.getArtifacts(MavenPomArtifact::class.java) }
        .filterIsInstance<org.gradle.api.artifacts.result.ResolvedArtifactResult>().firstOrNull()?.file

/** Declared licences, from the module's POM or the nearest parent that has some. */
fun licencesOf(coordinates: String): List<String> {
    var next: String? = coordinates
    repeat(4) {
        val (group, name, version) = next?.split(":") ?: return emptyList()
        val (licences, parent) = readPom(pomOf(group, name, version) ?: error("no POM for $group:$name:$version"))
        if (licences.isNotEmpty()) return licences
        next = parent
    }
    return emptyList()
}

fun isApache2(licence: String) = Regex("""apache.*2\.0""", RegexOption.IGNORE_CASE).containsMatchIn(licence)
fun isMit(licence: String) = Regex("""^(the )?mit( license)?$""", RegexOption.IGNORE_CASE).matches(licence)

/** The kept licence texts of a module, if any. */
fun keptTextsOf(module: String): List<File> {
    val (_, name, version) = module.split(":")
    return File(keptTexts, "$name-$version").listFiles()?.sorted() ?: emptyList()
}

val androidLibraries = tasks.register("androidLibraries") {
    description = "Lists the release APK's Android libraries with the licences their POMs declare."
    inputs.property("modules", modules)
    inputs.dir(keptTexts)
    outputs.dir(noticesDir)
    notCompatibleWithConfigurationCache("reads POMs through the dependency resolution API")
    doLast {
        val lines = modules.get().map { module ->
            val licences = licencesOf(module)
            val mit = licences.none(::isApache2) && licences.any(::isMit) &&
                keptTextsOf(module).any { it.readText().contains("Permission is hereby granted, free of charge") }
            if (licences.none(::isApache2) && !mit) {
                throw GradleException(
                    "$module: its POM offers ${licences.ifEmpty { listOf("no licence") }}, not the Apache License 2.0 " +
                        "(or the MIT License, with its text kept in licence-texts/android)",
                )
            }
            "$module: ${licences.joinToString(" OR ")}" + if (mit) " (text below)" else ""
        }
        val texts = modules.get().flatMap { module ->
            keptTextsOf(module).map { "[$module, ${it.name}]\n\n${it.readText().trim()}\n" }
        }
        val out = noticesDir.get().file("notices/android-libraries.txt").asFile
        out.parentFile.mkdirs()
        out.writeText(
            "Android libraries in this app, with the licences their published POMs declare.\n" +
                "Rift uses each under the Apache License 2.0 (apache-2.0.txt) where it offers it,\n" +
                "otherwise under the MIT License, whose text is below.\n\n" +
                lines.joinToString("\n") + "\n" +
                texts.joinToString("") { "\n" + "-".repeat(72) + "\n" + it }
        )
    }
}

// Every task that reads the assets: merging them, and lint's models of
// the sources (a release build runs lint and fails on an undeclared input).
tasks.matching {
    (it.name.startsWith("merge") && it.name.endsWith("Assets")) || it.name.contains("lint", ignoreCase = true)
}.configureEach {
    dependsOn(androidLibraries)
}
