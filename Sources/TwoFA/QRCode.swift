import AppKit
import CoreImage

enum QRCode {
    /// Returns the text of every QR code found in the image.
    static func messages(in image: NSImage) -> [String] {
        guard let tiff = image.tiffRepresentation, let ciImage = CIImage(data: tiff) else { return [] }
        return messages(in: ciImage)
    }

    static func messages(in image: CIImage) -> [String] {
        let detector = CIDetector(
            ofType: CIDetectorTypeQRCode,
            context: nil,
            options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
        )
        return (detector?.features(in: image) ?? []).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }
}
