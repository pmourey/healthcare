// Function to toggle health-related checkboxes
function toggleHealthChecks(checkbox, isSelectAll = false) {
    // Get all health-related checkboxes
    const healthCheckboxes = document.querySelectorAll('input[name^="health_"]');

    if (isSelectAll) {
        // If this is the "select all" checkbox
        const isChecked = checkbox.checked;
        healthCheckboxes.forEach(healthBox => {
            healthBox.checked = isChecked;
        });
    } else {
        // If this is an individual checkbox, check if we need to update "select all"
        const selectAllCheckbox = document.getElementById('select_all_health');
        const allChecked = Array.from(healthCheckboxes).every(box => box.checked);
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = allChecked;
        }
    }
}

// Function to toggle blood marker checkboxes
function toggleBloodChecks(checkbox, isSelectAll = false) {
    // Get all blood marker checkboxes
    const bloodCheckboxes = document.querySelectorAll('input[name^="blood_"]');

    if (isSelectAll) {
        // If this is the "select all" checkbox
        const isChecked = checkbox.checked;
        bloodCheckboxes.forEach(bloodBox => {
            bloodBox.checked = isChecked;
        });
    } else {
        // If this is an individual checkbox, check if we need to update "select all"
        const selectAllCheckbox = document.getElementById('select_all_blood');
        const allChecked = Array.from(bloodCheckboxes).every(box => box.checked);
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = allChecked;
        }
    }
}
