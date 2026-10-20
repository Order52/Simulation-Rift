// The Android libraries in this APK and the licences their POMs declare
// (§25), written to build/generated-notices/android/notices/
// android-libraries.txt for the module's assets. Rift uses every library
// under the Apache License 2.0, whose text the APK carries, so the build
// fails if a library's POM does not offer it. Texts a library's own
// archive does not carry (JNA's, and libffi's, which its native code links)
// are kept in licence-texts/android/<artifact>-<version>/ and appended.
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

val androidLibraries = tasks.register("androidLibraries") {
    description = "Lists the release APK's Android libraries with the licences their POMs declare."
    inputs.property("modules", modules)
    inputs.dir(keptTexts)
    outputs.dir(noticesDir)
    notCompatibleWithConfigurationCache("reads POMs through the dependency resolution API")
    doLast {
        val lines = modules.get().map { module ->
            val licences = licencesOf(module)
            if (licences.none(::isApache2)) {
                throw GradleException("$module: its POM offers ${licences.ifEmpty { listOf("no licence") }}, not the Apache License 2.0")
            }
            "$module: ${licences.joinToString(" OR ")}"
        }
        val texts = modules.get().flatMap { module ->
            val (_, name, version) = module.split(":")
            (File(keptTexts, "$name-$version").listFiles()?.sorted() ?: emptyList())
                .map { "[$module, ${it.name}]\n\n${it.readText().trim()}\n" }
        }
        val out = noticesDir.get().file("notices/android-libraries.txt").asFile
        out.parentFile.mkdirs()
        out.writeText(
            "Android libraries in this app, with the licences their published POMs declare.\n" +
                "Each offers the Apache License 2.0 (apache-2.0.txt), under which Rift uses it.\n\n" +
                lines.joinToString("\n") + "\n" +
                texts.joinToString("") { "\n" + "-".repeat(72) + "\n" + it }
        )
    }
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }.configureEach {
    dependsOn(androidLibraries)
}
