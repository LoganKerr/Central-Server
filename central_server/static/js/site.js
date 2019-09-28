$(document).ready(function() {

var candidateNum = 0; 
    $("#addNewCandidate").click(addCandidate);

function addCandidate() { 
    var newCandidate = $("<input type='text'</input>") 
        .attr("class", "form-control form-control-lg") 
        .attr("id", "candidates-" + candidateNum) 
        .attr("name", "candidates-" + candidateNum)
    $("#candidates").append(newCandidate); 
    candidateNum++; 
}

var voterNum = 0; 
    $("#addNewVoter").click(addVoter);

function addVoter() { 
    var newVoter = $("<input type='text'</input>") 
        .attr("class", "form-control form-control-lg") 
        .attr("id", "voters-" + voterNum) 
        .attr("name", "voters-" + voterNum) 
    $("#voters").append(newVoter); 
    voterNum++; 
}

addCandidate()
addVoter()

});