/**
 * The goal of this script is extracting all of the threats in the model and write them into a CSV file 
 * Threats are captured within different objects of the DFD graphs
 */


// Callback and synchronous file library
const fs = require('fs')
let threats = [];

// Load threat model JSON
var threatModel = JSON.parse(fs.readFileSync('./ddri_threat.json', 'utf8'));
// Scan through all the DFD diagram
for(i = 0; i < threatModel.detail.diagrams.length; i++){
    let currDiagram = threatModel.detail.diagrams[i];
    // Scan through all the cells within the diagram
    for(j = 0; j < currDiagram.diagramJson.cells.length; j++){
        let currCell = currDiagram.diagramJson.cells[j]
        // Skip cells that are dataflows, boundary, or has no threat
        if(currCell.type == 'tm.Flow' || currCell.type == 'tm.Boundary' || !currCell.threats) continue
        else {
            let target = currCell.attrs.text.text.replace(/\n/g, " ");
            // console.log(currCell.threats.length)
            currCell.threats.forEach(threat => {
                threats.push(
                    {
                        "title": threat.title,
                        "type": threat.type,
                        "target": target,
                        "description": threat.description,
                        "mitigation": threat.mitigation
                    }
                )
            })
        }
    }
}

console.log(threats);

const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const csvWriter = createCsvWriter({
  path: 'out.csv',
  header: [
    {id: 'title', title: 'Threat'},
    {id: 'type', title: 'Threat Type'},
    {id: 'target', title: 'Target'},
    {id: 'description', title: 'Description'},
    {id: 'mitigation', title: 'Mitigation'}
  ]
});

csvWriter
  .writeRecords(threats)
  .then(()=> console.log('The CSV file was written successfully'));