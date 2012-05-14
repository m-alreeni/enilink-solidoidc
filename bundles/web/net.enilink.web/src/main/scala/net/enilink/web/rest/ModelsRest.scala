package net.enilink.web.rest

import java.io.ByteArrayOutputStream
import scala.collection.JavaConversions._
import org.eclipse.core.runtime.Platform
import org.eclipse.core.runtime.QualifiedName
import org.eclipse.core.runtime.content.IContentDescription
import org.eclipse.core.runtime.content.IContentType
import net.enilink.komma.model.ModelCore
import net.enilink.komma.core.URIImpl
import net.enilink.core.ModelSetManager
import net.liftweb.http.ContentType
import net.liftweb.http.InMemoryResponse
import net.liftweb.http.LiftResponse
import net.liftweb.http.LiftResponse
import net.liftweb.http.NotFoundResponse
import net.liftweb.http.Req
import net.liftweb.http.rest.RestHelper
import net.liftweb.common.Box
import net.liftweb.common.Full

object ModelsRest extends RestHelper {
  /**
   * Simple in-memory response for RDF data.
   */
  case class RdfResponse(data: Array[Byte], contentDescription: IContentDescription, headers: List[(String, String)], code: Int) extends LiftResponse {
    def toResponse = {
      val typeName = contentDescription.getProperty(mimeTypeProp)
      InMemoryResponse(data, ("Content-Length", data.length.toString) :: ("Content-Type", typeName + "; charset=utf-8") :: headers, Nil, code)
    }
  }

  /**
   * If the headers and the suffix say nothing about the
   * response type, should we default to RDF/XML.  By default,
   * no, override to change the behavior.
   */
  protected def defaultGetAsRdfXml: Boolean = false

  /**
   * Retrieve all registered RDF content types (those with a special mimeType property) and store them in a map.
   */
  val mimeType = "^(.+)/(.+)$".r
  lazy val mimeTypeProp = new QualifiedName(ModelCore.PLUGIN_ID, "mimeType")
  lazy val rdfContentTypes: Map[(String, String), IContentType] = Platform.getContentTypeManager.getAllContentTypes.flatMap {
    contentType =>
      contentType.getDefaultDescription.getProperty(mimeTypeProp) match {
        case mimeType(superType, subType) => List((superType -> subType) -> contentType)
        case superType: String => List((superType -> "*") -> contentType)
        case _ => Nil
      }
  }.toMap

  /**
   * Tests requests for wanting RDF data.
   */
  protected trait RdfTest {
    def testResponse_?(r: Req): Boolean = getResponseContentType(r) isDefined
  }

  /**
   * Find best matching content type for the request using accept headers.
   */
  def matchTypeByWeight(r: Req) = {
    object FindContentType {
      // extractor for partial function below
      def unapply(ct: ContentType) = rdfContentTypes.find(e => ct.matches(e._1))
    }
    r.weightedAccept.collectFirst { case FindContentType(key, value) => (key, value) }
  }

  /**
   * Find best matching content type for the suffix of the request URI.
   */
  def matchTypeByExtension(extension: String) = {
    rdfContentTypes.find(_._2.getFileSpecs(IContentType.FILE_EXTENSION_SPEC).contains(extension))
  }

  def getResponseContentType(r: Req) = {
    val uri = getUri(r)
    if ((r.weightedAccept.isEmpty || r.acceptsStarStar) && uri.fileExtension != null && defaultGetAsRdfXml) {
      Some(Platform.getContentTypeManager.getContentType("net.enilink.komma.contenttype.rdfxml"))
    } else {
      (if (uri.fileExtension != null) matchTypeByExtension(uri.fileExtension) else None) match {
        case Some((mimeType, cType)) if r.acceptsStarStar || r.weightedAccept.find(_.matches(mimeType)).isDefined => Some(cType)
        case _ => matchTypeByWeight(r).map(_._2)
      }
    }
  }

  def getUri(r: Req) = URIImpl.createURI( /*r.hostAndPath*/ "http://enilink.net" + r.uri)

  protected lazy val RdfGet = new TestGet with RdfTest

  /**
   * Serialize and return RDF data according to the requested content type.
   */
  def serveRdf(r: Req): Box[LiftResponse] = {
    val modelUri = getUri(r).trimFileExtension
    val model = ModelSetManager.INSTANCE.getModelSet.getModel(modelUri, false)
    if (model == null) Full(new NotFoundResponse("Model " + modelUri + " not found.")) else {
      getResponseContentType(r) map (_.getDefaultDescription) match {
        case Some(cd) =>
          val baos = new ByteArrayOutputStream
          model.save(baos, Map(classOf[IContentDescription] -> cd))
          Full(new RdfResponse(baos.toByteArray, cd, Nil, 200))
        case _ => None
      }
    }
  }

  serve {
    case "vocab" :: modelName RdfGet req if !modelName.isEmpty && modelName != List("index") => serveRdf(req)
  }
}