package sbom

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"

	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/model"
	"github.com/xmirrorsecurity/opensca-cli/v3/opensca/sca/filter"
)

type Sca struct{}

func (sca Sca) Language() model.Language {
	return model.Lan_None
}

func (sca Sca) Filter(relpath string) bool {
	return filter.SbomJson(relpath) || filter.SbomXml(relpath) || filter.SbomSpdx(relpath) || filter.SbomDsdx(relpath) || filter.SbomDbSbom(relpath)
}

func (sca Sca) Sca(ctx context.Context, parent *model.File, files []*model.File, call model.ResCallback) {
	for _, file := range files {
		if filter.SbomSpdx(file.Relpath()) {
			call(file, ParseSpdx(file))
			continue
		}
		if filter.SbomDsdx(file.Relpath()) {
			call(file, ParseDsdx(file))
			continue
		}
		if filter.SbomDbSbom(file.Relpath()) {
			call(file, ParseBomSWJson(file))
			continue
		}
		if filter.SbomJson(file.Relpath()) {
			var header map[string]json.RawMessage
			file.OpenReader(func(r io.Reader) { _ = json.NewDecoder(r).Decode(&header) })
			switch {
			case header["bomFormat"] != nil:
				call(file, ParseCdxJson(file))
			case header["spdxVersion"] != nil:
				call(file, ParseSpdxJson(file))
			case header["dsdx_version"] != nil:
				call(file, ParseDsdxJson(file))
			case header["software"] != nil:
				call(file, ParseBomSWJson(file))
			}
		}
		if filter.SbomXml(file.Relpath()) {
			var header struct {
				XMLName xml.Name
				Version string `xml:"dsdx_version"`
			}
			file.OpenReader(func(r io.Reader) { _ = xml.NewDecoder(r).Decode(&header) })
			switch {
			case strings.HasPrefix(header.XMLName.Space, "http://cyclonedx.org/schema/bom/"):
				call(file, ParseCdxXml(file))
			case header.Version != "":
				call(file, ParseDsdxXml(file))
			case header.XMLName.Local == "RDF" || header.XMLName.Local == "SpdxDocument":
				call(file, ParseSpdxXml(file))
			}
		}
	}
}
