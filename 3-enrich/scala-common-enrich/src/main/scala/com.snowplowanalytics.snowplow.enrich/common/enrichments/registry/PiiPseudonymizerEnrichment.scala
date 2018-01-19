/*
 * Copyright (c) 2017-2018 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */

package com.snowplowanalytics
package snowplow.enrich
package common.enrichments.registry

// Scala
import scala.collection.JavaConverters._

// Iglu
import iglu.client.validation.ProcessingMessageMethods._
import iglu.client.{SchemaCriterion, SchemaKey}

// Scala libraries
import org.json4s.JValue
import org.json4s.JsonAST._
import org.json4s.jackson.JsonMethods
import org.json4s.jackson.JsonMethods.{compact, parse, render}
import org.json4s.DefaultFormats

// Java
import java.security.{MessageDigest, NoSuchAlgorithmException}
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.{ObjectNode, TextNode}
import com.fasterxml.jackson.databind.node.ArrayNode
import com.jayway.jsonpath.spi.json.JacksonJsonNodeJsonProvider
import com.jayway.jsonpath.{Configuration, JsonPath => JJsonPath, Option => JOption}
import com.jayway.jsonpath.MapFunction

// Scalaz
import scalaz._
import Scalaz._

// This project
import common.ValidatedNelMessage
import common.utils.MapTransformer.TransformMap
import common.utils.ScalazJson4sUtils

/**
 * PiiField trait. This corresponds to a configuration top-level field (i.e. either a POJO or a JSON field) along with
 * a function to apply that strategy to a TransformMap.
 */
sealed trait PiiField {

  /**
   * Strategy for this field
   *
   * @return PiiStrategy a strategy to be applied to this field
   */
  def strategy: PiiStrategy

  /**
   * Name of the field (e.g. user_id or contexts)
   *
   * @return feldName the name of the field
   */
  def fieldName: String

  /**
   * Gets a transform map as defined in the enrichment manager and applies a function if a field matches the specified
   * field in the config to the specified field after the field has applied its own function. This applies only to
   * strings.
   *
   * @param transformMap The transform map from the enrichment manager
   * @return a transfromMap for the enrichment manager with the specified fields modified
   */
  def transformer(transformMap: TransformMap): TransformMap =
    transformMap.collect {
      case (inputField: String, (tf: Function2[String, String, Validation[String, String]], outputField: String))
          if (outputField == fieldName) =>
        (inputField, ((arg1: String, arg2: String) => tf.tupled.andThen(_.map(applyStrategy))((arg1, arg2)), outputField))
    }
  protected def applyStrategy(fieldValue: String): String
}

/**
 * PiiStrategy trait. This corresponds to a strategy to apply to a single field. Currently only only String input is
 * supported.
 */
sealed trait PiiStrategy {
  def scramble(clearText: String): String
}

/**
 * Companion object. Lets us create a PiiPseudonymizerEnrichment
 * from a JValue.
 */
object PiiPseudonymizerEnrichment extends ParseableEnrichment {

  implicit val json4sFormats = DefaultFormats

  override val supportedSchema =
    SchemaCriterion("com.snowplowanalytics.snowplow.enrichments", "pii_enrichment_config", "jsonscehma", 1, 0, 0)

  def parse(config: JValue, schemaKey: SchemaKey): ValidatedNelMessage[PiiPseudonymizerEnrichment] = {
    for {
      conf <- matchesSchema(config, schemaKey)
      enabled = ScalazJson4sUtils.extract[Boolean](conf, "enabled").toOption.getOrElse(false)
      piiFields        <- ScalazJson4sUtils.extract[List[JObject]](conf, "parameters", "pii").leftMap(_.getMessage)
      strategyFunction <- extractStrategyFunction(config)
      hashFunction     <- getHashFunction(strategyFunction)
      piiFieldList     <- extractFields(piiFields, PiiStrategyPseudonymize(hashFunction))
    } yield if (enabled) PiiPseudonymizerEnrichment(piiFieldList) else PiiPseudonymizerEnrichment(List())
  }.leftMap(_.toProcessingMessageNel)

  private def getHashFunction(strategyFunction: String): Validation[String, MessageDigest] =
    try {
      MessageDigest.getInstance(strategyFunction).success
    } catch {
      case e: NoSuchAlgorithmException =>
        s"Could not parse PII enrichment config: ${e.getMessage()}".failure
    }

  private def extractFields(piiFields: List[JObject], strategy: PiiStrategy) =
    piiFields.map {
      case JObject(List(("pojo", JObject(List(("field", JString(fieldName))))))) => PiiPojo(strategy, fieldName).success
      case JObject(List(("json", jsonField))) =>
        (extractString(jsonField, "field") |@|
          extractString(jsonField, "schemaCriterion").flatMap(sc => SchemaCriterion.parse(sc).leftMap(_.getMessage)) |@|
          extractString(jsonField, "jsonPath")) { (fieldName: String, sc: SchemaCriterion, jsonPath: String) =>
          PiiJson(strategy, fieldName, sc, jsonPath)
        }
      case json => s"PII Configuration: pii field does not include 'pojo' nor 'json' fields. Got: [${compact(json)}]".failure
    }.sequenceU

  private def extractString(jValue: JValue, field: String): Validation[String, String] =
    ScalazJson4sUtils.extract[String](jValue, field).leftMap(_.getMessage)

  private def extractStrategyFunction(config: JValue) =
    ScalazJson4sUtils
      .extract[String](config, "parameters", "strategy", "pseudonymize", "hashFunction")
      .leftMap(_.getMessage)

  private def matchesSchema(config: JValue, schemaKey: SchemaKey): Validation[String, JValue] =
    if (supportedSchema.matches(schemaKey)) {
      config.success
    } else {
      "Schema key %s is not supported. A '%s' enrichment must have schema '%s'."
        .format(schemaKey, supportedSchema.name, supportedSchema)
        .failure
    }
}

/**
 * The PiiPseudonymizerEnrichment runs after all other enrichments to find fields that are configured as PII (personally
 * identifiable information) and apply some anonymization (currently only psudonymizantion) on them. Currently a single
 * strategy for all the fields is supported due to the config format, and there is only one implemented strategy,
 * however the enrichment supports a strategy per field configuration.
 *
 * The user may specify two types of fields POJO or JSON. A POJO field is effectively a scalar field in the
 * EnrichedEvent, whereas a JSON is a "context" formatted field (a JSON string in "contexts" field in enriched event)
 *
 * @param fieldList a lits of configured PiiFields
 */
case class PiiPseudonymizerEnrichment(fieldList: List[PiiField]) extends Enrichment {
  def transformer(transformMap: TransformMap): TransformMap = transformMap ++ fieldList.map(_.transformer(transformMap)).reduce(_ ++ _)

}

/**
 * Specifies a field in POJO and the strategy that should be applied to it.
 * @param strategy the strategy that should be applied
 * @param fieldName the field where the strategy will be applied
 */
final case class PiiPojo(strategy: PiiStrategy, fieldName: String) extends PiiField {
  override def applyStrategy(fieldValue: String): String = strategy.scramble(fieldValue)
}

/**
 * Specifies a strategy to use, a field (should be "contexts") where the JSON can be found, a schema criterion to
 * discriminate which contexts to apply this strategy to, and a json path within the contexts where this strategy will
 * be apllied (the path may correspond to multiple fields).
 *
 * @param strategy the strategy that should be applied
 * @param fieldName the field in POJO where the json is to be found
 * @param schemaCriterion the schema for which the strategy will be applied
 * @param jsonPath the path where the strategy will be applied
 */
final case class PiiJson(strategy: PiiStrategy, fieldName: String, schemaCriterion: SchemaCriterion, jsonPath: String) extends PiiField {
  implicit val json4sFormats = DefaultFormats

  override def applyStrategy(fieldValue: String): String =
    compact(render(parse(fieldValue).transformField {
      case JField("data", contents) =>
        ("data", contents.transform {
          case contexts: JArray =>
            contexts.transform {
              case JObject(context) =>
                val fields: Map[String, JValue] = List("schema", "data").flatMap(k => context.toMap.get(k).map(v => (k -> v))).toMap
                fields
                  .get("schema")
                  .flatMap(s =>
                    SchemaKey.parse(s.extract[String]).map(schemaCriterion.matches).toOption match {
                      case Some(matches) if matches =>
                        fields.get("data").flatMap(d => Some(JObject(List(("schema", s), ("data", jsonPathReplace(d))))))
                      case default => None
                  })
                  .getOrElse(JObject(context))
            }
        })
    }))

  // Configuration for JsonPath
  private val JsonPathConf =
    Configuration.builder().options(JOption.SUPPRESS_EXCEPTIONS).jsonProvider(new JacksonJsonNodeJsonProvider()).build()

  /**
   * Replaces a value in the given context data with the result of applying the strategy that value.
   *
   */
  private def jsonPathReplace(jValue: JValue): JValue = {
    val objectNode      = JsonMethods.mapper.valueToTree[ObjectNode](jValue)
    val documentContext = JJsonPath.using(JsonPathConf).parse(objectNode)
    documentContext.map(
      jsonPath,
      new MapFunction {
        override def map(currentValue: AnyRef, configuration: Configuration): AnyRef = currentValue match {
          case s: String => strategy.scramble(s)
          case a: ArrayNode =>
            a.elements.asScala.map {
              case t: TextNode     => strategy.scramble(t.asText())
              case default: AnyRef => default
            }
          case default: AnyRef => default
        }
      }
    )
    JsonMethods.fromJsonNode(documentContext.json[JsonNode]())
  }
}

/**
 * Implements a pseudonymization strategy using any algorithm known to MessageDigest
 * @param hashFunction the MessageDigest function to apply
 */
case class PiiStrategyPseudonymize(hashFunction: MessageDigest) extends PiiStrategy {
  val TextEncoding                                 = "UTF-8"
  override def scramble(clearText: String): String = hash(clearText)
  def hash(text: String): String                   = String.format("%064x", new java.math.BigInteger(1, hashFunction.digest(text.getBytes(TextEncoding))))
}
