inThisBuild(
  List(
    scalaVersion := "3.8.1",
    organization := "io.github.arashi01",
    description := "",
    startYear := Some(2026),
    homepage := Some(url("https://github.com/arashi01/zio-jwt")),
    semanticdbEnabled := true,
    version := versionSetting.value,
    dynver := versionSetting.toTaskable.toTask.value,
    versionScheme := Some("semver-spec"),
    licenses := List("MIT" -> url("https://opensource.org/licenses/MIT")),
    scmInfo := Some(
      ScmInfo(
        url("https://github.com/arashi01/zio-jwt"),
        "scm:git:https://github.com/arashi01/zio-jwt.git",
        Some("scm:git:git@github.com:arashi01/zio-jwt.git")
      )
    )
  ) ++ formattingSettings
)

val libraries = new {
  val boilerplate = Def.setting("io.github.arashi01" %%% "boilerplate" % "0.4.0")
  val `jsoniter-scala-core` = Def.setting("com.github.plokhotnyuk.jsoniter-scala" %%% "jsoniter-scala-core" % "2.38.8")
  val `jsoniter-scala-macros` = `jsoniter-scala-core`(_.withName("jsoniter-scala-macros"))
  val munit = Def.setting("org.scalameta" %%% "munit" % "1.2.1")
  val `munit-scalacheck` = Def.setting("org.scalameta" %%% "munit-scalacheck" % "1.2.0")
  val `munit-zio` = Def.setting("com.github.poslegm" %%% "munit-zio" % "0.4.0")
  val `scala-java-time` = Def.setting("io.github.cquiroz" %%% "scala-java-time" % "2.6.0")
  val zio = Def.setting("dev.zio" %%% "zio" % "2.1.24")
  val `zio-http` = Def.setting("dev.zio" %% "zio-http" % "3.8.1")
}

val `zio-jwt-core` =
  crossProject(JVMPlatform, JSPlatform, NativePlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Pure)
    .in(file("modules/core"))
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .nativeSettings(nativeSettings)
    .settings(libraryDependencies += libraries.boilerplate.value)
    .settings(libraryDependencies += libraries.zio.value)
    .jvmSettings(
      Compile / unmanagedSourceDirectories += baseDirectory.value.getParentFile / "jvm" / "src" / "main" / "scala",
      Test / unmanagedSourceDirectories += baseDirectory.value.getParentFile / "jvm" / "src" / "test" / "scala"
    )
    .jsSettings(libraryDependencies += libraries.`scala-java-time`.value % Provided)
    .nativeSettings(libraryDependencies += libraries.`scala-java-time`.value % Provided)

val `zio-jwt-jsoniter` =
  crossProject(JVMPlatform, JSPlatform, NativePlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Pure)
    .in(file("modules/jsoniter"))
    .dependsOn(`zio-jwt-core`)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .nativeSettings(nativeSettings)
    .settings(libraryDependencies += libraries.`jsoniter-scala-core`.value)
    .settings(libraryDependencies += libraries.`jsoniter-scala-macros`.value % Provided)

val `zio-jwt` =
  crossProject(JVMPlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Full)
    .in(file("modules/jwt"))
    .dependsOn(`zio-jwt-core`, `zio-jwt-jsoniter` % Test)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)

val `zio-http-jwt` =
  project
    .in(file("modules/zio-http"))
    .dependsOn(`zio-jwt`.jvm)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(libraryDependencies += libraries.`zio-http`.value)

val `zio-jwt-jvm` =
  project
    .in(file(".jvm"))
    .settings(publish / skip := true)
    .aggregate(
      `zio-jwt-core`.jvm,
      `zio-jwt`.jvm,
      `zio-http-jwt`,
      `zio-jwt-jsoniter`.jvm
    )

val `zio-jwt-js` =
  project
    .in(file(".js"))
    .settings(publish / skip := true)
    .aggregate(
      `zio-jwt-core`.js,
      `zio-jwt-jsoniter`.js
    )

val `zio-jwt-native` =
  project
    .in(file(".native"))
    .settings(publish / skip := true)
    .aggregate(
      `zio-jwt-core`.native,
      `zio-jwt-jsoniter`.native
    )

val `zio-jwt-root` =
  project
    .in(file("."))
    .settings(publish / skip := true)
    .aggregate(
      `zio-jwt-jvm`,
      `zio-jwt-js`,
      `zio-jwt-native`
    )

def nativeSettings = List(
  dependencyOverrides += "org.scala-native" %%% "test-interface" % buildinfo.BuildInfo.scalaNativeVersion % Test
)

def baseCompilerOptions = List(
  // Language features
  "-language:experimental.macros",
  "-language:higherKinds",
  "-language:implicitConversions",
  "-language:strictEquality",

  // Kind projector / macros
  "-Xkind-projector",
  "-Xmax-inlines:64",

  // Core checks
  "-unchecked",
  "-deprecation",
  "-feature",
  "-explain",

  // Warning flags
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Wunused:implicits",
  "-Wunused:explicits",
  "-Wunused:imports",
  "-Wunused:locals",
  "-Wunused:params",
  "-Wunused:privates",

  // Scala 3-specific checks
  "-Yrequire-targetName",
  "-Ycheck-reentrant",
  "-Ycheck-mods"
)

def compilerOptions = baseCompilerOptions ++ List(
  "-Yexplicit-nulls",
  "-Xcheck-macros",
  "-Werror"
  // Suppress warning for intentional inline class instantiation in codec derivation
//  "-Wconf:msg=New anonymous class definition will be duplicated at each inline site:s"
)

def compilerSettings = List(
  Compile / compile / scalacOptions ++= compilerOptions,
  Test / compile / scalacOptions ++= baseCompilerOptions,
  Compile / doc / scalacOptions := Nil,
  Test / doc / scalacOptions := Nil
)

def formattingSettings = List(
  scalafmtDetailedError := true,
  scalafmtPrintDiff := true
)

def unitTestSettings: List[Setting[?]] = List(
  libraryDependencies ++= List(
    libraries.munit.value % Test,
    libraries.`munit-scalacheck`.value % Test,
    libraries.`scala-java-time`.value % Test,
    libraries.`munit-zio`.value % Test,
  ),
  testFrameworks += new TestFramework("munit.Framework")
)

def fileHeaderSettings: List[Setting[?]] =
  List(
    headerLicense := {
      val developmentTimeline = {
        import java.time.Year
        val start = startYear.value.get
        val current: Int = Year.now.getValue
        if (start == current) s"$current" else s"$start, $current"
      }
      Some(HeaderLicense.MIT(developmentTimeline, "Ali Rashid."))
    },
    headerEmptyLine := false
  )

def pgpSettings: List[Setting[?]] = List(
  PgpKeys.pgpSelectPassphrase := None,
  usePgpKeyHex(System.getenv("SIGNING_KEY_ID"))
)

def platformSourceDirectory(platform: String): Setting[Seq[File]] = sourceDirectories += (sourceDirectory.value / platform)

def versionSetting: Def.Initialize[String] = Def.setting(
  dynverGitDescribeOutput.value.mkVersion(
    (in: sbtdynver.GitDescribeOutput) =>
      if (!in.isSnapshot()) in.ref.dropPrefix
      else {
        val ref = in.ref.dropPrefix
        // Strip pre-release or build metadata (e.g., "-m.1" or "+build.5")
        val base = ref.takeWhile(c => c != '-' && c != '+')
        val numericParts =
          base.split("\\.").toList.map(_.trim).flatMap(s => scala.util.Try(s.toInt).toOption)

        if (numericParts.nonEmpty) {
          val incremented = numericParts.updated(numericParts.length - 1, numericParts.last + 1)
          s"${incremented.mkString(".")}-SNAPSHOT"
        } else {
          s"$base-SNAPSHOT"
        }
      },
    "SNAPSHOT"
  )
)

def publishSettings: List[Setting[?]] = pgpSettings ++: List(
  packageOptions += Package.ManifestAttributes(
    "Build-Jdk" -> System.getProperty("java.version"),
    "Specification-Title" -> name.value,
    "Specification-Version" -> Keys.version.value,
    "Implementation-Title" -> name.value
  ),
  publishTo := {
    if (Keys.version.value.toLowerCase.contains("snapshot"))
      Some("central-snapshots".at("https://central.sonatype.com/repository/maven-snapshots/"))
    else localStaging.value
  },
  pomIncludeRepository := (_ => false),
  publishMavenStyle := true,
  developers := List(
    Developer(
      "arashi01",
      "Ali Rashid",
      "https://github.com/arashi01",
      url("https://github.com/arashi01")
    )
  )
)

addCommandAlias("format", "scalafixAll; scalafmtAll; scalafmtSbt; headerCreateAll")
addCommandAlias("check", "scalafixAll --check; scalafmtCheckAll; scalafmtSbtCheck; headerCheckAll")
