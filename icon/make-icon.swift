import AppKit
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

// Draws the app icon at every size the iconset needs.
//
// Generated rather than hand-drawn so it can be re-rendered at any size, and so
// the geometry is inspectable. The motif fuses the two things the app does: the
// arches read as fingerprint ridges and as a padlock shackle at the same time,
// sitting on a lock body.
//
//   swift icon/make-icon.swift <output-dir>

let args = CommandLine.arguments
let outDir = URL(fileURLWithPath: args.count > 1 ? args[1] : "icon/build")
try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

func srgb(_ r: Double, _ g: Double, _ b: Double, _ a: Double = 1) -> CGColor {
    CGColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: a)
}

// Deep blue-graphite: dark enough for light ridges to carry at 16px, not black.
let bgTop = srgb(58, 74, 107)
let bgBottom = srgb(16, 22, 38)
let ridge = srgb(233, 238, 248)
let ridgeDim = srgb(176, 190, 214)
let accent = srgb(245, 166, 35)

func drawIcon(size: CGFloat, into ctx: CGContext) {
    ctx.setAllowsAntialiasing(true)
    ctx.interpolationQuality = .high

    // Detail falls away as the canvas shrinks. Three nested ridges and a keyhole
    // turn to mush at 16px, so small sizes get a bolder, simpler mark rather than
    // a faithful reduction of the large one.
    let detail = size >= 128 ? 2 : (size >= 32 ? 1 : 0)

    // macOS icons leave a margin for their shadow, but small ones use less of it,
    // otherwise there is nothing left to read.
    let inset = size * (detail == 0 ? 0.06 : 0.09)
    let art = CGRect(x: inset, y: inset, width: size - inset * 2, height: size - inset * 2)
    let corner = art.width * 0.2237  // Apple's squircle approximation

    // Background
    let squircle = CGPath(roundedRect: art, cornerWidth: corner, cornerHeight: corner,
                          transform: nil)
    ctx.saveGState()
    ctx.addPath(squircle)
    ctx.clip()
    let space = CGColorSpaceCreateDeviceRGB()
    if let gradient = CGGradient(colorsSpace: space,
                                 colors: [bgTop, bgBottom] as CFArray,
                                 locations: [0, 1]) {
        ctx.drawLinearGradient(gradient,
                               start: CGPoint(x: art.midX, y: art.maxY),
                               end: CGPoint(x: art.midX, y: art.minY),
                               options: [])
    }
    ctx.restoreGState()

    // Everything below is in art-relative units so the design scales exactly.
    let u = art.width
    let cx = art.midX
    let bodyW = u * (detail == 2 ? 0.44 : 0.50)
    let bodyH = u * (detail == 2 ? 0.29 : 0.33)
    let bodyY = art.minY + u * (detail == 2 ? 0.17 : 0.15)
    let body = CGRect(x: cx - bodyW / 2, y: bodyY, width: bodyW, height: bodyH)
    let bodyCorner = bodyH * 0.28

    // Fingerprint ridges, doubling as the shackle. Drawn before the body so their
    // ends tuck behind it. In a y-up context the upper half of a circle is swept
    // clockwise from pi to 0, passing through pi/2 at the top.
    let shackleBase = body.maxY - u * 0.015
    ctx.setLineCap(.round)

    // Below 128px the shackle has to be narrow enough that its legs disappear
    // behind the body. Wider, and the arch and the body fuse into one blob with no
    // dark gap between them — which is what a padlock silhouette lives or dies on.
    let radii: [CGFloat]
    let lineWidth: CGFloat
    switch detail {
    case 0: radii = [0.195];                lineWidth = u * 0.100
    case 1: radii = [0.190];                lineWidth = u * 0.085
    default: radii = [0.335, 0.245, 0.155]; lineWidth = u * 0.072
    }

    for (i, factor) in radii.enumerated() {
        ctx.setLineWidth(lineWidth * (i == 0 ? 1.0 : 0.86))
        ctx.setStrokeColor(i == 0 ? ridge : ridgeDim)
        ctx.beginPath()
        ctx.addArc(center: CGPoint(x: cx, y: shackleBase), radius: u * factor,
                   startAngle: .pi, endAngle: 0, clockwise: true)
        ctx.strokePath()
    }

    // The live-touch ridge: one short accent arc over the top left, the only warm
    // element and the thing that stops it reading as a plain padlock. Below 128px
    // it is a few stray pixels of orange, so it goes.
    if detail >= 2 {
        ctx.setLineWidth(lineWidth * 0.86)
        ctx.setStrokeColor(accent)
        ctx.beginPath()
        ctx.addArc(center: CGPoint(x: cx, y: shackleBase), radius: u * 0.245,
                   startAngle: .pi * 0.94, endAngle: .pi * 0.58, clockwise: true)
        ctx.strokePath()
    }

    // Lock body
    ctx.setFillColor(ridge)
    ctx.addPath(CGPath(roundedRect: body, cornerWidth: bodyCorner,
                       cornerHeight: bodyCorner, transform: nil))
    ctx.fillPath()

    // Keyhole, only once there are enough pixels for it to be a shape rather
    // than a smudge.
    if size >= 64 {
        ctx.setFillColor(bgBottom)
        let kr = bodyH * 0.17
        let kcx = body.midX
        let kcy = body.midY + bodyH * 0.09
        ctx.fillEllipse(in: CGRect(x: kcx - kr, y: kcy - kr, width: kr * 2, height: kr * 2))
        let stemW = kr * 0.86
        ctx.fill(CGRect(x: kcx - stemW / 2, y: body.minY + bodyH * 0.20,
                        width: stemW, height: kcy - (body.minY + bodyH * 0.20)))
    }
}

func render(size: Int) -> CGImage? {
    let s = CGFloat(size)
    guard let ctx = CGContext(data: nil, width: size, height: size,
                              bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
    else { return nil }
    drawIcon(size: s, into: ctx)
    return ctx.makeImage()
}

func write(_ image: CGImage, to url: URL) throws {
    guard let dest = CGImageDestinationCreateWithURL(
        url as CFURL, UTType.png.identifier as CFString, 1, nil) else {
        throw NSError(domain: "icon", code: 1)
    }
    CGImageDestinationAddImage(dest, image, nil)
    guard CGImageDestinationFinalize(dest) else { throw NSError(domain: "icon", code: 2) }
}

// iconutil's expected names: base size, and @2x drawn at double resolution.
let entries: [(name: String, pixels: Int)] = [
    ("icon_16x16", 16), ("icon_16x16@2x", 32),
    ("icon_32x32", 32), ("icon_32x32@2x", 64),
    ("icon_128x128", 128), ("icon_128x128@2x", 256),
    ("icon_256x256", 256), ("icon_256x256@2x", 512),
    ("icon_512x512", 512), ("icon_512x512@2x", 1024),
]

for entry in entries {
    guard let image = render(size: entry.pixels) else {
        FileHandle.standardError.write(Data("failed at \(entry.name)\n".utf8))
        exit(1)
    }
    try write(image, to: outDir.appendingPathComponent("\(entry.name).png"))
}

// A contact sheet at true pixel sizes on both backgrounds, because an icon that
// looks fine blown up can still be unreadable in a Dock or a Finder list.
let sheetSizes = [16, 32, 64, 128, 256]
let pad = 24
let sheetW = sheetSizes.reduce(0, +) + pad * (sheetSizes.count + 1)
let sheetH = 256 + pad * 3 + 256

if let sheet = CGContext(data: nil, width: sheetW, height: sheetH,
                         bitsPerComponent: 8, bytesPerRow: 0,
                         space: CGColorSpaceCreateDeviceRGB(),
                         bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) {
    // Top band light, bottom band dark.
    sheet.setFillColor(srgb(245, 245, 247))
    sheet.fill(CGRect(x: 0, y: sheetH / 2, width: sheetW, height: sheetH / 2))
    sheet.setFillColor(srgb(30, 30, 32))
    sheet.fill(CGRect(x: 0, y: 0, width: sheetW, height: sheetH / 2))

    for (bandIndex, bandBottom) in [sheetH / 2, 0].enumerated() {
        var x = pad
        for s in sheetSizes {
            if let img = render(size: s) {
                let y = bandBottom + (sheetH / 2 - s) / 2
                sheet.draw(img, in: CGRect(x: x, y: y, width: s, height: s))
            }
            x += s + pad
        }
        _ = bandIndex
    }
    if let img = sheet.makeImage() {
        try write(img, to: outDir.deletingLastPathComponent()
            .appendingPathComponent("preview.png"))
    }
}

print("wrote \(entries.count) images to \(outDir.path)")
